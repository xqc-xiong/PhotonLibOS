// Offline tests for the OSS SSE request/response model, against a loopback
// HTTP server and a recording authenticator (no credentials, no external
// network). Scope: the main flows of the SSE fix.

#include "../../test/gtest.h"

#include <photon/common/alog.h>
#include <photon/common/estring.h>
#include <photon/net/http/server.h>
#include <photon/net/socket.h>
#include <photon/photon.h>
#include <photon/thread/thread.h>

#include <cerrno>
#include <map>
#include <string>
#include <vector>

#include "../oss.h"

using namespace photon::objstore;
using namespace photon::net;
using namespace photon::net::http;

namespace {
SseOptions kms(const char* key = "key-1") {
  SseOptions s;
  s.algorithm = "KMS";
  s.kms_key_id = key;
  return s;
}
SseOptions aes() {
  SseOptions s;
  s.algorithm = "AES256";
  return s;
}
}  // namespace

// Pure helpers (no photon runtime).

TEST(OssSseHelpers, opt_value_and_legacy_aggregate_init) {
  OptValue<std::string> v;
  EXPECT_FALSE(v.has_value());
  v.set(std::string("a"));
  EXPECT_EQ(v.value(), "a");
  OptValue<std::string> copy = v;
  EXPECT_EQ(copy.value(), "a");
  v.set(std::string());  // present-but-empty stays distinct from missing
  EXPECT_TRUE(v.has_value());
  v.reset();
  EXPECT_FALSE(v.has_value());

  uint64_t crc = 1;
  std::string etag;
  // The historical two-field aggregate initialization must keep working.
  ObjectUploadOptions o{&crc, &etag};
  EXPECT_EQ(o.expected_crc64, &crc);
  EXPECT_EQ(o.etag, &etag);
  EXPECT_FALSE(o.sse.has_value());
  EXPECT_EQ(o.sse_response, nullptr);
}

TEST(OssSseHelpers, sse_header_and_verify_helpers) {
  CommonHeaders<4096> h;
  EXPECT_EQ(add_sse_headers(h, kms()), 0);
  EXPECT_EQ(h.get_value("x-oss-server-side-encryption"), "KMS");
  EXPECT_EQ(h.get_value("x-oss-server-side-encryption-key-id"), "key-1");
  errno = 0;  // duplicate insert is reported, not ignored
  EXPECT_EQ(add_sse_headers(h, kms()), -1);
  EXPECT_EQ(errno, EEXIST);
  CommonHeaders<32> tiny;
  errno = 0;  // out-of-buffer is reported, not silently dropped
  EXPECT_EQ(add_sse_headers(tiny, aes()), -1);
  EXPECT_EQ(errno, ENOBUFS);

  SseResponse out;
  parse_sse_response(h, &out);
  EXPECT_EQ(out.algorithm.value(), "KMS");
  EXPECT_EQ(out.kms_key_id.value(), "key-1");
  EXPECT_EQ(verify_sse_response(kms(), true, &out), SseVerification::Matched);
  EXPECT_EQ(verify_sse_response(kms("key-2"), true, &out),
            SseVerification::Mismatch);
  CommonHeaders<4096> no_key;
  no_key.insert("x-oss-server-side-encryption", "KMS");
  SseResponse out2;
  parse_sse_response(no_key, &out2);
  // A missing key-id echo is tolerated at Init but rejected on final writes.
  EXPECT_EQ(verify_sse_response(kms(), false, &out2), SseVerification::Matched);
  EXPECT_EQ(verify_sse_response(kms(), true, &out2), SseVerification::Missing);
}

// Loopback HTTP fixture.

struct ScriptedResponse {
  int status = 200;
  std::map<std::string, std::string> headers;
  std::string body;
};

ScriptedResponse ok200(std::string body = "", const char* alg = nullptr,
                       const char* key = nullptr) {
  ScriptedResponse r;
  if (alg) r.headers["x-oss-server-side-encryption"] = alg;
  if (key) r.headers["x-oss-server-side-encryption-key-id"] = key;
  r.headers["ETag"] = "\"e1\"";
  r.body = std::move(body);
  return r;
}

ScriptedResponse abort204() {
  ScriptedResponse r;
  r.status = 204;
  return r;
}

const char* kInitXml =
    "<InitiateMultipartUploadResult><UploadId>U1</UploadId>"
    "</InitiateMultipartUploadResult>";
const char* kCompleteXml =
    "<CompleteMultipartUploadResult></CompleteMultipartUploadResult>";
const char* kCopyXml = "<CopyObjectResult></CopyObjectResult>";

class RecordingAuthenticator : public Authenticator {
 public:
  int sign_count = 0;
  std::map<std::string, std::string> last_headers;
  int sign(Headers& headers, const SignParameters&) override {
    ++sign_count;
    last_headers.clear();
    for (auto kv : headers)
      last_headers[std::string(kv.first)] = std::string(kv.second);
    return 0;
  }
  void set_credentials(CredentialParameters&&) override {}
};

class OssSseHttpTest : public ::testing::Test {
 protected:
  ISocketServer* tcp_server = nullptr;
  HTTPServer* http_server = nullptr;
  photon::mutex mu;
  std::vector<std::map<std::string, std::string>> requests;
  std::vector<std::string> targets;
  std::vector<ScriptedResponse> script;
  size_t next_script = 0;

  static int handler_entry(void* arg, Request& req, Response& resp,
                           std::string_view) {
    return static_cast<OssSseHttpTest*>(arg)->handle(req, resp);
  }

  int handle(Request& req, Response& resp) {
    auto len = req.headers.content_length();
    if (len > 0) {
      std::string drain(len, '\0');
      req.read(&drain[0], len);
    }
    ScriptedResponse out;
    {
      SCOPED_LOCK(mu);
      std::map<std::string, std::string> hdrs;
      for (auto kv : req.headers)
        hdrs[std::string(kv.first)] = std::string(kv.second);
      requests.push_back(std::move(hdrs));
      targets.push_back(std::string(req.target()));
      if (next_script < script.size()) {
        out = script[next_script++];
      } else if (!script.empty()) {
        out = script.back();
      }
    }
    resp.set_result(out.status);
    for (const auto& kv : out.headers) resp.headers.insert(kv.first, kv.second);
    resp.headers.content_length(out.body.size());
    if (!out.body.empty()) resp.write((void*)out.body.data(), out.body.size());
    return 0;
  }

  void SetUp() override {
    photon::init(photon::INIT_EVENT_DEFAULT, photon::INIT_IO_NONE);
    tcp_server = new_tcp_socket_server();
    tcp_server->timeout(1000ULL * 1000 * 10);
    tcp_server->bind_v4localhost();
    tcp_server->listen();
    http_server = new_http_server();
    http_server->add_handler({this, &OssSseHttpTest::handler_entry});
    tcp_server->set_handler(http_server->get_connection_handler());
    tcp_server->start_loop();
  }

  void TearDown() override {
    delete http_server;
    delete tcp_server;
    photon::fini();
  }

  using CustomHeaders = std::vector<std::pair<std::string, std::string>>;
  photon::objstore::Client* make_client(RecordingAuthenticator** auth_out,
                                        CustomHeaders custom = {}) {
    ClientOptions opts;
    opts.endpoint = "oss-test.example.com";
    opts.bucket = "test-bucket";
    opts.proxy = estring().appends("http://127.0.0.1:",
                                   tcp_server->getsockname().port);
    opts.retry_times = 0;
    opts.custom_headers = std::move(custom);
    *auth_out = new RecordingAuthenticator();
    return new_oss_client(opts, *auth_out);
  }

  ssize_t do_put(photon::objstore::Client* c, ObjectUploadOptions& opts) {
    char data[1] = {7};
    iovec iov{data, 1};
    return c->put_object("test-obj", &iov, 1, opts);
  }
};

// Main flows of the SSE fix.

TEST_F(OssSseHttpTest, put_sends_headers_and_verifies_match) {
  script = {ok200("", "KMS", "key-1")};
  RecordingAuthenticator* auth;
  auto client = make_client(&auth);
  DEFER(delete client);
  ObjectUploadOptions opts;
  opts.sse.set(kms());
  SseResponse out;
  opts.sse_response = &out;
  EXPECT_EQ(do_put(client, opts), 1);
  ASSERT_EQ(requests.size(), 1u);
  EXPECT_EQ(requests[0]["x-oss-server-side-encryption"], "KMS");
  EXPECT_EQ(requests[0]["x-oss-server-side-encryption-key-id"], "key-1");
  // The SSE headers were already present at signing time.
  EXPECT_EQ(auth->last_headers["x-oss-server-side-encryption"], "KMS");
  EXPECT_EQ(out.verification, SseVerification::Matched);
}

TEST_F(OssSseHttpTest, put_missing_echo_fails_with_and_without_output) {
  script = {ok200(), ok200()};
  RecordingAuthenticator* auth;
  auto client = make_client(&auth);
  DEFER(delete client);
  // A null sse_response only means "not interested in details"; the
  // verification still runs and fails the write.
  ObjectUploadOptions a;
  a.sse.set(aes());
  errno = 0;
  EXPECT_EQ(do_put(client, a), -1);
  EXPECT_EQ(errno, EIO);
  ObjectUploadOptions b;
  b.sse.set(aes());
  SseResponse out;
  b.sse_response = &out;
  EXPECT_EQ(do_put(client, b), -1);
  EXPECT_EQ(out.verification, SseVerification::Missing);
  EXPECT_EQ(requests.size(), 2u);
}

TEST_F(OssSseHttpTest, put_rejects_invalid_policy_and_conflicting_headers) {
  RecordingAuthenticator* auth;
  auto client = make_client(&auth);
  DEFER(delete client);
  SseOptions bad[3];
  bad[0].algorithm = "";  // present-but-empty is not "not requested"
  bad[1].algorithm = "SM4";
  bad[2] = aes();
  bad[2].kms_key_id = "k";  // key id is only valid with KMS
  for (const auto& p : bad) {
    ObjectUploadOptions o;
    o.sse.set(p);
    errno = 0;
    EXPECT_EQ(do_put(client, o), -1);
    EXPECT_EQ(errno, EINVAL);
  }
  EXPECT_EQ(auth->sign_count, 0);

  // A typed policy mixed with a global SSE custom header is rejected too.
  RecordingAuthenticator* auth2;
  auto client2 = make_client(&auth2, {{"x-oss-server-side-encryption", "KMS"}});
  DEFER(delete client2);
  ObjectUploadOptions o;
  o.sse.set(kms());
  errno = 0;
  EXPECT_EQ(do_put(client2, o), -1);
  EXPECT_EQ(errno, EINVAL);
  EXPECT_EQ(auth2->sign_count, 0);
  EXPECT_TRUE(requests.empty());
}

TEST_F(OssSseHttpTest, copy_sends_policy_and_source_if_match) {
  script = {ok200(kCopyXml, "AES256"), ok200(kCopyXml)};
  RecordingAuthenticator* auth;
  auto client = make_client(&auth);
  DEFER(delete client);
  ObjectCopyOptions opts;
  opts.sse.set(aes());
  opts.source_if_match = "etag-src";
  SseResponse out;
  opts.sse_response = &out;
  EXPECT_EQ(client->copy_object("src-obj", "dst-obj", opts), 0);
  ASSERT_EQ(requests.size(), 1u);
  EXPECT_EQ(requests[0]["x-oss-copy-source-if-match"], "etag-src");
  EXPECT_EQ(requests[0]["x-oss-server-side-encryption"], "AES256");
  EXPECT_EQ(out.verification, SseVerification::Matched);
  // Same call without an output pointer and without an SSE echo: fails.
  ObjectCopyOptions opts2;
  opts2.sse.set(aes());
  errno = 0;
  EXPECT_EQ(client->copy_object("src-obj", "dst-obj", opts2), -1);
  EXPECT_EQ(errno, EIO);
}

TEST_F(OssSseHttpTest, multipart_init_snapshot_and_part_rules) {
  script = {ok200(kInitXml, "KMS"), ok200(), ok200(kCompleteXml, "KMS", "key-1")};
  RecordingAuthenticator* auth;
  auto client = make_client(&auth);
  DEFER(delete client);
  MultipartUploadOptions mpu;
  mpu.sse.set(kms("key-1"));
  void* ctx = nullptr;
  ASSERT_EQ(client->init_multipart_upload("mp-obj", &ctx, mpu), 0);
  ASSERT_NE(ctx, nullptr);
  ASSERT_EQ(requests.size(), 1u);
  EXPECT_EQ(requests[0]["x-oss-server-side-encryption"], "KMS");
  // Mutating the caller's options after Init must not change the policy.
  mpu.sse.set(kms("key-9"));
  char data[4] = {0};
  iovec iov{data, sizeof(data)};
  ObjectUploadOptions part_opts;
  EXPECT_EQ(client->upload_part(ctx, &iov, 1, 1, part_opts),
            (ssize_t)sizeof(data));
  ObjectUploadOptions copts;
  SseResponse out;
  copts.sse_response = &out;
  EXPECT_EQ(client->complete_multipart_upload(ctx, copts), 0);
  EXPECT_EQ(out.verification, SseVerification::Matched);
  // Part and Complete must not carry SSE creation headers.
  ASSERT_EQ(requests.size(), 3u);
  EXPECT_EQ(requests[1].count("x-oss-server-side-encryption"), 0u);
  EXPECT_EQ(requests[2].count("x-oss-server-side-encryption"), 0u);
}

TEST_F(OssSseHttpTest, init_wrong_echo_aborts_with_and_without_output) {
  script = {ok200(kInitXml, "AES256"), abort204(),
            ok200(kInitXml, "AES256"), abort204()};
  RecordingAuthenticator* auth;
  auto client = make_client(&auth);
  DEFER(delete client);
  MultipartUploadOptions m1;
  m1.sse.set(kms());
  SseResponse out;
  m1.sse_response = &out;
  void* ctx = nullptr;
  errno = 0;
  EXPECT_EQ(client->init_multipart_upload("mp-obj", &ctx, m1), -1);
  EXPECT_EQ(errno, EIO);
  EXPECT_EQ(ctx, nullptr);
  EXPECT_EQ(out.verification, SseVerification::Mismatch);
  MultipartUploadOptions m2;  // no output pointer: same cleanup
  m2.sse.set(kms());
  EXPECT_EQ(client->init_multipart_upload("mp-obj", &ctx, m2), -1);
  EXPECT_EQ(ctx, nullptr);
  // Each failed Init is followed by a best-effort Abort (DELETE uploadId).
  ASSERT_EQ(targets.size(), 4u);
  EXPECT_NE(targets[1].find("U1"), std::string::npos);
  EXPECT_NE(targets[3].find("U1"), std::string::npos);
}

TEST_F(OssSseHttpTest, multipart_misuse_rejected) {
  script = {ok200(kInitXml), abort204(), ok200(kInitXml)};
  RecordingAuthenticator* auth;
  auto client = make_client(&auth);
  DEFER(delete client);
  void* ctx = nullptr;
  MultipartUploadOptions mpu;
  ASSERT_EQ(client->init_multipart_upload("mp-obj", &ctx, mpu), 0);
  // UploadPart / Append reject a present policy without consuming ctx.
  char data[4] = {0};
  iovec iov{data, sizeof(data)};
  ObjectUploadOptions popts;
  popts.sse.set(aes());
  errno = 0;
  EXPECT_EQ(client->upload_part(ctx, &iov, 1, 1, popts), -1);
  EXPECT_EQ(errno, EINVAL);
  EXPECT_EQ(client->append_object("a-obj", &iov, 1, 0, popts), -1);
  EXPECT_EQ(requests.size(), 1u);
  EXPECT_EQ(client->abort_multipart_upload(ctx), 0);
  EXPECT_EQ(requests.size(), 2u);

  // Complete with any caller-provided policy is a usage error, rejected
  // without sending anything (and this one consumes its context).
  void* ctx2 = nullptr;
  ASSERT_EQ(client->init_multipart_upload("mp-obj", &ctx2, mpu), 0);
  ObjectUploadOptions copts;
  copts.sse.set(kms());
  errno = 0;
  EXPECT_EQ(client->complete_multipart_upload(ctx2, copts), -1);
  EXPECT_EQ(errno, EINVAL);
  EXPECT_EQ(requests.size(), 3u);
}
