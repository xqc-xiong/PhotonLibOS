// Offline tests for the OSS SSE request/response model, against a loopback
// HTTP server and a recording authenticator (no credentials, no external
// network). Scope: safe request encoding and response observations only.

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

TEST(OssSseHelpers, response_fields_preserve_presence_and_own_values) {
  CommonHeaders<4096> h;
  h.insert("x-oss-server-side-encryption", "KMS");
  h.insert("x-oss-server-side-encryption-key-id", "key-1");
  h.insert("x-oss-server-side-data-encryption", "AES256");
  h.insert("x-oss-request-id", "request-1");
  SseResponse out;
  parse_sse_response(h, &out);
  EXPECT_TRUE(out.received);
  ASSERT_TRUE(out.algorithm.has_value());
  EXPECT_EQ(out.algorithm.value(), "KMS");
  EXPECT_EQ(out.kms_key_id.value(), "key-1");
  EXPECT_EQ(out.data_algorithm.value(), "AES256");
  EXPECT_EQ(out.request_id, "request-1");
  h.reset();
  EXPECT_EQ(out.kms_key_id.value(), "key-1");
  h.insert("x-oss-server-side-encryption-key-id", "");
  parse_sse_response(h, &out);
  EXPECT_TRUE(out.received);
  EXPECT_FALSE(out.algorithm.has_value());
  EXPECT_TRUE(out.kms_key_id.has_value());
  EXPECT_TRUE(out.kms_key_id.value().empty());
  ObjectHeaderMeta meta;
  meta.sse = out;
  meta.reset();
  EXPECT_FALSE(meta.sse.received);
  EXPECT_FALSE(meta.sse.kms_key_id.has_value());
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
    // The loopback fixture is plain HTTP, not a CONNECT/TLS proxy.
    opts.endpoint = "http://oss-test.example.com";
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

TEST_F(OssSseHttpTest, put_sends_headers_and_observes_response) {
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
  EXPECT_TRUE(out.received);
  EXPECT_EQ(out.algorithm.value(), "KMS");
  EXPECT_EQ(out.kms_key_id.value(), "key-1");
}

TEST_F(OssSseHttpTest, put_missing_echo_succeeds_with_and_without_output) {
  script = {ok200(), ok200()};
  RecordingAuthenticator* auth;
  auto client = make_client(&auth);
  DEFER(delete client);
  // Missing SSE fields do not turn a successful business response into
  // an error. The caller owns strict verification, with or without output.
  ObjectUploadOptions a;
  a.sse.set(aes());
  errno = 0;
  EXPECT_EQ(do_put(client, a), 1);
  ObjectUploadOptions b;
  b.sse.set(aes());
  SseResponse out;
  b.sse_response = &out;
  EXPECT_EQ(do_put(client, b), 1);
  EXPECT_TRUE(out.received);
  EXPECT_FALSE(out.algorithm.has_value());
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
  EXPECT_TRUE(out.received);
  EXPECT_EQ(out.algorithm.value(), "AES256");
  // Without an output pointer or echo, business success remains success.
  ObjectCopyOptions opts2;
  opts2.sse.set(aes());
  errno = 0;
  EXPECT_EQ(client->copy_object("src-obj", "dst-obj", opts2), 0);
}

TEST_F(OssSseHttpTest, multipart_sends_creation_headers_only_at_init) {
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
  // The service fixed encryption at Init; Complete does not resend a policy.
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
  EXPECT_TRUE(out.received);
  EXPECT_EQ(out.algorithm.value(), "KMS");
  EXPECT_EQ(out.kms_key_id.value(), "key-1");
  // Part and Complete must not carry SSE creation headers.
  ASSERT_EQ(requests.size(), 3u);
  EXPECT_EQ(requests[1].count("x-oss-server-side-encryption"), 0u);
  EXPECT_EQ(requests[2].count("x-oss-server-side-encryption"), 0u);
}

TEST_F(OssSseHttpTest, init_wrong_echo_is_observed_and_caller_owns_abort) {
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
  EXPECT_EQ(client->init_multipart_upload("mp-obj", &ctx, m1), 0);
  ASSERT_NE(ctx, nullptr);
  EXPECT_TRUE(out.received);
  EXPECT_EQ(out.algorithm.value(), "AES256");
  EXPECT_EQ(requests.size(), 1u);
  EXPECT_EQ(client->abort_multipart_upload(ctx), 0);
  ctx = nullptr;
  MultipartUploadOptions m2;
  m2.sse.set(kms());
  EXPECT_EQ(client->init_multipart_upload("mp-obj", &ctx, m2), 0);
  ASSERT_NE(ctx, nullptr);
  EXPECT_EQ(requests.size(), 3u);
  EXPECT_EQ(client->abort_multipart_upload(ctx), 0);
  ctx = nullptr;
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
  SseResponse out;
  out.received = true;
  popts.sse_response = &out;
  errno = 0;
  EXPECT_EQ(client->upload_part(ctx, &iov, 1, 1, popts), -1);
  EXPECT_EQ(errno, EINVAL);
  EXPECT_FALSE(out.received);
  out.received = true;
  EXPECT_EQ(client->append_object("a-obj", &iov, 1, 0, popts), -1);
  EXPECT_FALSE(out.received);
  EXPECT_EQ(requests.size(), 1u);
  EXPECT_EQ(client->abort_multipart_upload(ctx), 0);
  EXPECT_EQ(requests.size(), 2u);

  // Complete with any caller-provided policy is a usage error, rejected
  // without sending anything (and this one consumes its context).
  void* ctx2 = nullptr;
  ASSERT_EQ(client->init_multipart_upload("mp-obj", &ctx2, mpu), 0);
  ObjectUploadOptions copts;
  copts.sse.set(kms());
  out.received = true;
  copts.sse_response = &out;
  std::string etag = "unchanged";
  copts.etag = &etag;
  errno = 0;
  EXPECT_EQ(client->complete_multipart_upload(ctx2, copts), -1);
  ctx2 = nullptr;
  EXPECT_EQ(errno, EINVAL);
  EXPECT_FALSE(out.received);
  EXPECT_EQ(etag, "unchanged");
  EXPECT_EQ(requests.size(), 3u);
}

TEST_F(OssSseHttpTest, header_capacity_and_control_chars_fail_before_send) {
  RecordingAuthenticator* auth;
  auto client = make_client(&auth);
  DEFER(delete client);
  int body_calls = 0;
  auto writer = [&](IStream*) -> ssize_t {
    ++body_calls;
    return 1;
  };
  BodyWriter body = writer;
  ObjectUploadOptions put;
  auto huge = kms();
  huge.kms_key_id = std::string(128 * 1024, 'k');
  put.sse.set(huge);
  SseResponse observed;
  observed.received = true;
  put.sse_response = &observed;
  EXPECT_EQ(client->put_object("obj", 1, body, put), -1);
  EXPECT_EQ(errno, ENOBUFS);
  EXPECT_FALSE(observed.received);
  MultipartUploadOptions init;
  init.sse.set(huge);
  void* ctx = nullptr;
  EXPECT_EQ(client->init_multipart_upload("obj", &ctx, init), -1);
  EXPECT_EQ(errno, ENOBUFS);
  EXPECT_EQ(ctx, nullptr);
  ObjectCopyOptions copy;
  copy.source_if_match = std::string(128 * 1024, 'e');
  EXPECT_EQ(client->copy_object("src", "dst", copy), -1);
  EXPECT_EQ(errno, ENOBUFS);
  copy.source_if_match = "etag\r\nInjected: value";
  EXPECT_EQ(client->copy_object("src", "dst", copy), -1);
  EXPECT_EQ(errno, EINVAL);
  for (const auto& key : std::vector<std::string>{"key\r\nInjected: value", std::string("a\0b", 3)}) {
    SseOptions invalid = kms();
    invalid.kms_key_id = key;
    put.sse.set(invalid);
    EXPECT_EQ(client->put_object("obj", 1, body, put), -1);
    EXPECT_EQ(errno, EINVAL);
  }
  EXPECT_EQ(auth->sign_count, 0);
  EXPECT_EQ(body_calls, 0);
  EXPECT_TRUE(requests.empty());
}

TEST_F(OssSseHttpTest, differing_response_is_returned_not_verified) {
  script = {ok200("", "AES256"), ok200(kCopyXml, "KMS", "other-key"), ok200(kInitXml, "KMS", "key-1"),
            ok200(kCompleteXml, "KMS", "other-key")};
  RecordingAuthenticator* auth;
  auto client = make_client(&auth);
  DEFER(delete client);
  SseResponse observed;
  ObjectUploadOptions put;
  put.sse.set(kms());
  put.sse_response = &observed;
  EXPECT_EQ(do_put(client, put), 1);
  EXPECT_TRUE(observed.received);
  EXPECT_EQ(observed.algorithm.value(), "AES256");
  ObjectCopyOptions copy;
  copy.sse.set(kms());
  copy.sse_response = &observed;
  EXPECT_EQ(client->copy_object("src", "dst", copy), 0);
  EXPECT_EQ(observed.kms_key_id.value(), "other-key");
  MultipartUploadOptions init;
  init.sse.set(kms());
  void* ctx = nullptr;
  ASSERT_EQ(client->init_multipart_upload("obj", &ctx, init), 0);
  ObjectUploadOptions complete;
  complete.sse_response = &observed;
  std::string etag;
  complete.etag = &etag;
  EXPECT_EQ(client->complete_multipart_upload(ctx, complete), 0);
  ctx = nullptr;
  EXPECT_TRUE(observed.received);
  EXPECT_EQ(observed.kms_key_id.value(), "other-key");
  EXPECT_EQ(etag, "\"e1\"");
}

TEST_F(OssSseHttpTest, complete_missing_echo_succeeds_without_observation) {
  script = {ok200(kInitXml, "KMS"), ok200(kCompleteXml)};
  RecordingAuthenticator* auth;
  auto client = make_client(&auth);
  DEFER(delete client);
  MultipartUploadOptions init;
  init.sse.set(kms());
  void* ctx = nullptr;
  ASSERT_EQ(client->init_multipart_upload("obj", &ctx, init), 0);
  ObjectUploadOptions complete;
  EXPECT_EQ(client->complete_multipart_upload(ctx, complete), 0);
  ctx = nullptr;
  EXPECT_EQ(requests.size(), 2u);
}

TEST_F(OssSseHttpTest, successful_response_remains_observable_on_crc_failure) {
  auto response = ok200("", "KMS", "key-1");
  response.headers["x-oss-hash-crc64ecma"] = "123";
  auto completed = ok200(kCompleteXml, "KMS", "key-1");
  completed.headers["x-oss-hash-crc64ecma"] = "123";
  script = {response, ok200(kInitXml, "KMS", "key-1"), completed};
  RecordingAuthenticator* auth;
  auto client = make_client(&auth);
  DEFER(delete client);
  uint64_t expected_crc = 999;
  std::string etag = "unchanged";
  SseResponse observed;
  ObjectUploadOptions put{&expected_crc, &etag};
  put.sse.set(kms());
  put.sse_response = &observed;
  EXPECT_EQ(do_put(client, put), -1);
  EXPECT_EQ(errno, EIO);
  EXPECT_TRUE(observed.received);
  EXPECT_EQ(observed.kms_key_id.value(), "key-1");
  EXPECT_EQ(etag, "unchanged");
  MultipartUploadOptions init;
  init.sse.set(kms());
  void* ctx = nullptr;
  ASSERT_EQ(client->init_multipart_upload("obj", &ctx, init), 0);
  ObjectUploadOptions complete{&expected_crc, &etag};
  complete.sse_response = &observed;
  EXPECT_EQ(client->complete_multipart_upload(ctx, complete), -1);
  ctx = nullptr;
  EXPECT_EQ(errno, EIO);
  EXPECT_TRUE(observed.received);
  EXPECT_EQ(etag, "unchanged");
}

TEST_F(OssSseHttpTest, business_errors_do_not_publish_success_observations) {
  script = {ok200("<Error><Code>InternalError</Code></Error>"), ok200(kInitXml),
            ok200("<Error><Code>InternalError</Code></Error>")};
  RecordingAuthenticator* auth;
  auto client = make_client(&auth);
  DEFER(delete client);
  SseResponse observed;
  observed.received = true;
  ObjectCopyOptions copy;
  copy.sse.set(kms());
  copy.sse_response = &observed;
  EXPECT_EQ(client->copy_object("src", "dst", copy), -1);
  EXPECT_EQ(errno, EIO);
  EXPECT_FALSE(observed.received);
  MultipartUploadOptions init;
  void* ctx = nullptr;
  ASSERT_EQ(client->init_multipart_upload("obj", &ctx, init), 0);
  ObjectUploadOptions complete;
  complete.sse_response = &observed;
  observed.received = true;
  EXPECT_EQ(client->complete_multipart_upload(ctx, complete), -1);
  ctx = nullptr;
  EXPECT_EQ(errno, EIO);
  EXPECT_FALSE(observed.received);
}

TEST_F(OssSseHttpTest, kms_without_key_id_reports_service_selected_key) {
  script = {ok200("", "KMS", "service-key")};
  RecordingAuthenticator* auth;
  auto client = make_client(&auth);
  DEFER(delete client);
  ObjectUploadOptions put;
  put.sse.set(kms(""));
  SseResponse observed;
  put.sse_response = &observed;
  EXPECT_EQ(do_put(client, put), 1);
  ASSERT_EQ(requests.size(), 1u);
  EXPECT_EQ(requests[0].count("x-oss-server-side-encryption-key-id"), 0u);
  EXPECT_TRUE(observed.received);
  EXPECT_EQ(observed.kms_key_id.value(), "service-key");
}

// An old-style consumer implements only the two-argument Init entry point.
class LegacySseClient : public photon::objstore::Client {
 public:
  int init_calls = 0;
  int put_bucket(std::string_view) override { return -1; }
  int delete_bucket() override { return -1; }
  int list_objects(std::string_view, ListObjectsCallback, ListObjectsParameters, std::string*, RequestTrace*) override {
    return -1;
  }
  int head_object(std::string_view, ObjectHeaderMeta&, RequestTrace*) override { return -1; }
  ssize_t get_object_range(std::string_view, off_t, size_t, BodyReader, ObjectHeaderMeta*, RequestTrace*) override {
    return -1;
  }
  int get_object_ranges(std::string_view, std::vector<GetRangeParameters>&, RequestTrace*) override { return -1; }
  int batch_get_objects(std::vector<GetObjectParameters>&, RequestTrace*) override { return -1; }
  ssize_t put_object(std::string_view, size_t, BodyWriter, ObjectUploadOptions&, RequestTrace*) override { return -1; }
  ssize_t append_object(std::string_view, const iovec*, int, off_t, ObjectUploadOptions&, RequestTrace*) override {
    return -1;
  }
  int copy_object(std::string_view, std::string_view, ObjectCopyOptions&) override { return -1; }
  int init_multipart_upload(std::string_view, void** ctx) override {
    ++init_calls;
    *ctx = this;
    return 0;
  }
  ssize_t upload_part(void*, size_t, int, BodyWriter, ObjectUploadOptions&) override { return -1; }
  int upload_part_copy(void*, off_t, size_t, int, std::string_view, ObjectPartCopyOptions&) override { return -1; }
  int complete_multipart_upload(void*, ObjectUploadOptions&) override { return -1; }
  int abort_multipart_upload(void*) override { return -1; }
  int delete_objects(const std::vector<std::string_view>&, std::string_view) override { return -1; }
  int delete_object(std::string_view) override { return -1; }
  int rename_object(std::string_view, std::string_view, bool) override { return -1; }
  int put_symlink(std::string_view, std::string_view) override { return -1; }
  int get_symlink(std::string_view, std::string&) override { return -1; }
  int get_object_meta(std::string_view, ObjectMeta&) override { return -1; }
  void set_credentials(CredentialParameters&&) override {}
};

TEST(OssSseHelpers, legacy_init_falls_back_without_dropping_requested_sse) {
  LegacySseClient legacy;
  photon::objstore::Client& client = legacy;
  MultipartUploadOptions init;
  SseResponse observed;
  observed.received = true;
  init.sse_response = &observed;
  void* ctx = nullptr;
  EXPECT_EQ(client.init_multipart_upload("obj", &ctx, init), 0);
  EXPECT_EQ(ctx, &legacy);
  EXPECT_EQ(legacy.init_calls, 1);
  EXPECT_FALSE(observed.received);
  init.sse.set(kms());
  observed.received = true;
  EXPECT_EQ(client.init_multipart_upload("obj", &ctx, init), -1);
  EXPECT_EQ(errno, EOPNOTSUPP);
  EXPECT_EQ(ctx, nullptr);
  EXPECT_EQ(legacy.init_calls, 1);
  EXPECT_FALSE(observed.received);
}
