/*
Copyright 2022 The Photon Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once
#include <inttypes.h>
#include <photon/common/callback.h>
#include <photon/common/iovector.h>
#include <photon/common/object.h>
#include <photon/common/ordered_span.h>
#include <photon/common/stream.h>
#include <photon/common/string_view.h>
#include <photon/net/http/headers.h>
#include <photon/net/http/verb.h>
#include <sys/uio.h>

#include <string>
#include <utility>
#include <vector>

namespace photon {
namespace objstore {

using StringKV = ordered_string_kv;

// A simple optional-value holder used by the OSS object model. It predates
// the SSE model below and must stay C++14-compatible: no std::optional, no
// throwing accessors. Check has_value()/operator bool() before value().
template <typename T>
class OptValue {
 public:
  bool has_value() const { return has_value_; }
  const T& value() const { return value_; }
  void set(T v) {
    value_ = std::move(v);
    has_value_ = true;
  }
  void reset() {
    value_ = {};
    has_value_ = false;
  }
  explicit operator bool() const { return has_value_; }

 private:
  T value_{};
  bool has_value_ = false;
};

// ---------------------------------------------------------------------------
// Server-side encryption (SSE) request/response model
//
// SseOptions is the typed, per-request SSE policy. It is only honored by the
// object-creation APIs (PutObject / InitiateMultipartUpload / CopyObject) and
// is applied right before signing so the headers participate in the
// signature. All other APIs reject a non-empty SseOptions input.
struct SseOptions {
  std::string algorithm;   // e.g. "AES256", "KMS"
  std::string kms_key_id;  // optional CMK id for the KMS algorithm
};

// Outcome of verifying a successful write response against the effective
// SSE policy.
enum class SseVerification : uint8_t {
  NotRequested = 0,  // no policy was attached to the request
  Matched,           // response carries the requested algorithm (and key id)
  Missing,           // required SSE fields are absent in the response
  Mismatch,          // SSE fields differ from the requested policy
};

// SSE-related fields observed on a single response. All strings are copied
// out of the HTTP header buffer; no string_view is retained.
struct SseResponse {
  OptValue<std::string> algorithm;
  OptValue<std::string> kms_key_id;
  // x-oss-server-side-data-encryption, e.g. AES256/SM4 for KMS objects.
  OptValue<std::string> data_algorithm;
  std::string request_id;
  SseVerification verification = SseVerification::NotRequested;
};

// Append SSE creation headers for PutObject/InitiateMultipartUpload/
// CopyObject. Must be called before signing. Returns 0 on success; -1 with
// errno set (EINVAL/EEXIST/ENOBUFS) when the headers cannot be added, in
// which case the request MUST NOT be signed or sent.
int add_sse_headers(photon::net::http::Headers& headers,
                    const SseOptions& sse);

// Extract SSE-related response headers into `out` (fully reset first).
void parse_sse_response(const photon::net::http::Headers& headers,
                        SseResponse* out);

// Verify a successful write response against the effective policy.
// `require_kms_key_id` is true for final write responses (Put/Copy/Complete):
// when the policy carries a key id, the response must echo it exactly.
// InitiateMultipartUpload passes false: a missing key-id echo is tolerated
// there, but a present one must still match.
SseVerification verify_sse_response(const SseOptions& expected,
                                    bool require_kms_key_id,
                                    SseResponse* observed);

std::string_view lookup_mime_type(std::string_view name);

static constexpr int OSS_MAX_PATH_LEN = 1023;

// IP version used to resolve the endpoint / proxy hostname, enforced via a
// private (client-owned) resolver on the underlying HTTP client.
enum class IPVersion : uint8_t {
  kBoth = 0,      // accept both IPv4 and IPv6 (default)
  kIPv4Only = 1,  // discard IPv6 addresses
  kIPv6Only = 2,  // discard IPv4 addresses
};

struct ClientOptions {
  std::string endpoint;
  std::string bucket;
  std::string region;
  std::string proxy;
  int max_list_ret_cnt = 1000;
  std::string user_agent = "Photon-ObjStore-Client";
  std::string bind_ips;
  // use path-style requests: http(s)://endpoint/bucket/object, instead of
  // the virtual-hosted style http(s)://bucket.endpoint/object
  bool path_style = false;
  uint64_t request_timeout_us = 60ull * 1000 * 1000;
  int retry_times = 2;

  // When the request timeouts or encounters 5xx error, we will
  // retry the request with times of the base interval.
  // For QPSLimit case, the policy is different. We will retry more
  // times until we have waited the "request time out" period.
  uint64_t retry_base_interval_us = 100'000;
  std::vector<std::pair<std::string, std::string>> custom_headers;

  IPVersion ip_version = IPVersion::kBoth;
};

struct ObjectMeta {
  uint8_t flags = 0;

  void reset() { flags = 0; }

#define DEFINE_OPTIONAL_FIELD(type, name, flag)                  \
  static_assert((flag) > 0 && ((flag) & ((flag) - 1)) == 0,      \
                "Flag must be a power of two");                  \
  static_assert(((flag) & ~((uint8_t)0xFF)) == 0,                \
                "Flag must fit within uint8_t bit range (0-7)"); \
  type name{};                                                   \
  bool has_##name() const { return flags & (flag); }             \
  void set_##name() { flags |= (flag); }                         \
  void set_##name(const type& value) {                           \
    name = value;                                                \
    flags |= (flag);                                             \
  }                                                              \
  void reset_##name() {                                          \
    name = {};                                                   \
    flags &= ~(flag);                                            \
  }

  DEFINE_OPTIONAL_FIELD(size_t, size, 1)
  DEFINE_OPTIONAL_FIELD(time_t, mtime, 1 << 1)
  DEFINE_OPTIONAL_FIELD(std::string, etag, 1 << 2)
  DEFINE_OPTIONAL_FIELD(std::string, type, 1 << 3)  // Appendable/Normal/...
};

struct ObjectHeaderMeta : public ObjectMeta {
  DEFINE_OPTIONAL_FIELD(std::string, storage_class, 1 << 4)
  DEFINE_OPTIONAL_FIELD(uint64_t, crc64, 1 << 5)

#undef DEFINE_OPTIONAL_FIELD

  // SSE attributes observed on HEAD. Independent field (not squeezed into
  // the uint8 flags); only meaningful as a transient HEAD result.
  SseResponse sse;
};

struct ObjectCopyOptions {
  bool overwrite = false;
  bool set_mime = false;

  OptValue<uint64_t> crc64;

  // inputs
  // Effective SSE policy for the destination object. OSS does not inherit
  // SSE attributes from the copy source, so the caller must pass an explicit
  // policy when encryption is expected.
  OptValue<SseOptions> sse;
  // Optional x-oss-copy-source-if-match constraint (source ETag), used to
  // bind the HEAD-based policy decision to the copied content.
  std::string source_if_match;

  // outputs
  SseResponse* sse_response = nullptr;
};

struct ObjectPartCopyOptions {
  OptValue<uint64_t> crc64;
};

struct ListObjectsParameters {
  uint8_t ver = 2;
  bool slash_delimiter = false;
  uint16_t max_keys = 0;
  std::string_view start_after = {};
};

struct ListObjectsCBParameters {
  std::string_view key;
  std::string_view etag;
  std::string_view type;
  size_t size = 0;
  time_t mtime = 0;
  bool is_com_prefix = false;
};

using ListObjectsCallback = Delegate<int, const ListObjectsCBParameters&>;

struct CredentialParameters {
  std::string accessKeyId;
  std::string accessKeySecret;
  std::string securityToken;
};

class Authenticator : Object {
 public:
  struct SignParameters {
    std::string_view region, endpoint, bucket, object;
    StringKV query_params;
    photon::net::http::Verb verb;
    bool invalidate_cache = false;
  };

  virtual int sign(photon::net::http::Headers& headers,
                   const SignParameters& params) = 0;

  virtual const CredentialParameters* get_credentials() { return nullptr; }

  // may be ignored for some implementations
  virtual void set_credentials(CredentialParameters&& credentials) = 0;
};

struct GetObjectParameters {
  std::string_view object;
  const iovec* iov = nullptr;
  int iovcnt = 0;
  off_t offset = 0;

  ObjectHeaderMeta* meta = nullptr;
  int result = -1;
};

// One byte range of a multi-range download, see get_object_ranges().
struct GetRangeParameters {
  const iovec* iov = nullptr;
  int iovcnt = 0;
  off_t offset = 0;
  ssize_t result = -1;  // filled size, or -1 if the range was not delivered
};

struct ObjectUploadOptions {
  // inputs
  const uint64_t *expected_crc64 = nullptr;

  // outputs
  std::string *etag = nullptr;

  // inputs (appended after the historical members so existing aggregate
  // initializations like {&crc64, &etag} keep compiling)
  // SSE creation policy. Only accepted by PutObject; UploadPart /
  // AppendObject / CompleteMultipartUpload reject a present value (multipart
  // encryption is fixed at Init time and Complete uses the context
  // snapshot).
  OptValue<SseOptions> sse;

  // outputs
  // Optional observation of the response SSE attributes. A nullptr does NOT
  // disable verification when a policy is requested; it only means the
  // caller is not interested in the details.
  SseResponse *sse_response = nullptr;
};

// Options for InitiateMultipartUpload. The effective SSE policy is fixed at
// Init time and snapshotted into the upload context; Complete verifies the
// final response against that snapshot.
struct MultipartUploadOptions {
  // inputs
  OptValue<SseOptions> sse;

  // outputs
  SseResponse *sse_response = nullptr;
};

// [WARNING] Retry-safety MUST be made sure. The framework re-calls from the 
// beginning on retry, so the callback must write the complete body 
// (content_length bytes) in one call, looping internally if needed. 
using BodyWriter = TempDelegate<ssize_t, IStream* /*output*/>;

// [WARNING] Retry-safety MUST be made sure. The framework re-calls from the 
// beginning on retry, so the callback must read the complete body in one call,
// looping internally if needed. 
// DO NOT merge BodyReader and BodyWriter to remind the caller whether to
// implement read or write.
using BodyReader = TempDelegate<ssize_t, IStream* /*input*/>;

class Client : public Object {
 public:
  virtual int put_bucket(std::string_view agent_bucket = {}) = 0;

  virtual int delete_bucket() = 0;

  virtual int list_objects(std::string_view prefix, ListObjectsCallback cb,
                           ListObjectsParameters = {},
                           std::string* marker = nullptr) = 0;

  virtual int head_object(std::string_view object, ObjectHeaderMeta& meta) = 0;

  // return value is the real size if the operation succeeds, otherwise
  // return -1
  ssize_t get_object_range(std::string_view object, char* buf, size_t size,
                           off_t offset, ObjectHeaderMeta* meta = nullptr) {
    return get_object_range(object, offset, size,
        [buf, size](IStream* input) -> ssize_t {
          return input->read(buf, size);
        }, meta);
  }
  ssize_t get_object_range(std::string_view object, const struct iovec* iov,
                           int iovcnt, off_t offset,
                           ObjectHeaderMeta* meta = nullptr) {
    iovector_view view((struct iovec*)iov, iovcnt);
    return get_object_range(object, offset, view.sum(),
        [iov, iovcnt](IStream* input) -> ssize_t {
          return input->readv(iov, iovcnt);
        }, meta);
  }

  virtual ssize_t get_object_range(std::string_view object, off_t offset,
                                   size_t cnt, BodyReader reader,
                                   ObjectHeaderMeta* meta = nullptr) = 0;

  // Download several byte ranges of one object within a single GET request,
  // relying on the OSS multi-range extension.
  // The ranges MUST be more than one, ascending and non-overlapping, and MUST
  // all fall inside the object. OSS does not reject a violating list, it
  // silently reorganizes it -- reordering or merging the ranges, or ignoring
  // the list and answering something else altogether -- and the reply reads
  // exactly like an answer to the list as sent. None of that reorganizing is
  // relied upon here: a violating list is rejected locally with EINVAL, which
  // is what leaves each response part mapping onto exactly one requested
  // range, verified part by part while the body is scattered into the iovs.
  // return 0 only if every iov is completely filled, -1 otherwise, with each
  // range's `result` set to its filled size for diagnosis.
  virtual int get_object_ranges(std::string_view object,
                                std::vector<GetRangeParameters>& ranges) = 0;

  // return value is the object count which data is successfully downloaded.
  // It's possible only some objects get to be downloaded successfully.
  // return -1 if some other errors happen.
  // The batch_get_objects interface works only when whitelisting enabled
  // at OSS server side.
  virtual int batch_get_objects(std::vector<GetObjectParameters>& params) = 0;

  // return value is the object size if the operation succeeds, otherwise
  // return -1.
  // if expected_crc64 is specified, we will compare the value with the
  // returned object crc64 to validate the object integrity.
  ssize_t put_object(std::string_view object, const char* buf, size_t size,
                     ObjectUploadOptions& opts) {
    return put_object(object, size,
        [buf, size](IStream* output) -> ssize_t {
          return output->write(buf, size);
        }, opts);
  }
  ssize_t put_object(std::string_view object, const struct iovec* iov,
                     int iovcnt, uint64_t* expected_crc64 = nullptr) {
    ObjectUploadOptions opts{.expected_crc64 = expected_crc64};
    return put_object(object, iov, iovcnt, opts);
  };
  ssize_t put_object(std::string_view object, const struct iovec* iov,
                     int iovcnt, ObjectUploadOptions& opts) {
    iovector_view view((struct iovec*)iov, iovcnt);
    return put_object(object, view.sum(),
        [iov, iovcnt](IStream* output) -> ssize_t {
          return output->writev(iov, iovcnt);
        }, opts);
  }

  virtual ssize_t put_object(std::string_view object, size_t cnt,
                             BodyWriter writer, ObjectUploadOptions& opts) = 0;

  // return value is the newly appended size if the operation succeeds,
  // otherwise return -1.
  // if expected_crc64 is specified, we will compare the value with the
  // returned object crc64 to validate the object integrity.
  ssize_t append_object(std::string_view object, const struct iovec* iov,
                        int iovcnt, off_t position,
                        uint64_t* expected_crc64 = nullptr) {
    ObjectUploadOptions opts{.expected_crc64 = expected_crc64};
    return append_object(object, iov, iovcnt, position, opts);
  };
  virtual ssize_t append_object(std::string_view object,
                                const struct iovec* iov, int iovcnt,
                                off_t position,
                                ObjectUploadOptions& opts) = 0;

  int copy_object(std::string_view src_object, std::string_view dst_object,
                  bool overwrite = false, bool set_mime = false) {
    ObjectCopyOptions opts;
    opts.overwrite = overwrite;
    opts.set_mime = set_mime;
    return copy_object(src_object, dst_object, opts);
  }

  virtual int copy_object(std::string_view src_object,
                          std::string_view dst_object,
                          ObjectCopyOptions& opts) = 0;

  virtual int init_multipart_upload(std::string_view object,
                                    void** context) = 0;

  // return value is the part size if the operation succeeds, otherwise
  // return -1.
  // if expected_crc64 is specified, we will compare the value with the
  // returned part crc64 to validate the part integrity.
  ssize_t upload_part(void* context, const char* buf, size_t size,
                      int part_number, ObjectUploadOptions& opts) {
    return upload_part(context, size, part_number,
        [buf, size](IStream* output) -> ssize_t {
          return output->write(buf, size);
        }, opts);
  }
  ssize_t upload_part(void* context, const struct iovec* iov, int iovcnt,
                      int part_number, uint64_t* expected_crc64 = nullptr) {
    ObjectUploadOptions opts{.expected_crc64 = expected_crc64};
    return upload_part(context, iov, iovcnt, part_number, opts);
  };
  ssize_t upload_part(void* context, const struct iovec* iov, int iovcnt,
                      int part_number, ObjectUploadOptions& opts) {
    iovector_view view((struct iovec*)iov, iovcnt);
    return upload_part(context, view.sum(), part_number,
        [iov, iovcnt](IStream* output) -> ssize_t {
          return output->writev(iov, iovcnt);
        }, opts);
  }

  virtual ssize_t upload_part(void* context, size_t cnt,
                              int part_number, BodyWriter writer,
                              ObjectUploadOptions& opts) = 0;

  int upload_part_copy(void* context, off_t offset, size_t count,
                       int part_number, std::string_view from = {}) {
    ObjectPartCopyOptions opts;
    return upload_part_copy(context, offset, count, part_number, from, opts);
  }

  virtual int upload_part_copy(void* context, off_t offset, size_t count,
                               int part_number, std::string_view from,
                               ObjectPartCopyOptions& opts) = 0;

  // if expected_crc64 is specified, we will compare the value with the
  // returned object crc64 to validate the object integrity.
  int complete_multipart_upload(void* context,
                                uint64_t* expected_crc64 = nullptr) {
    ObjectUploadOptions opts{.expected_crc64 = expected_crc64};
    return complete_multipart_upload(context, opts);
  }
  virtual int complete_multipart_upload(void* context,
                                        ObjectUploadOptions& opts) = 0;

  virtual int abort_multipart_upload(void* context) = 0;

  class MultipartUploadContext {
    Client* _client;
    void* _ctx;

   public:
    MultipartUploadContext(Client* client, void* ctx)
        : _client(client), _ctx(ctx) {}

    ssize_t upload(const struct iovec* iov, int iovcnt, int part_number,
                   uint64_t* expected_crc64 = nullptr) {
      return _client->upload_part(_ctx, iov, iovcnt, part_number,
                                  expected_crc64);
    }

    int copy(off_t offset, size_t count, int part_number,
             std::string_view from, ObjectPartCopyOptions& opts) {
      return _client->upload_part_copy(_ctx, offset, count, part_number, from,
                                       opts);
    }
    int copy(off_t offset, size_t count, int part_number,
             std::string_view from = {}) {
      ObjectPartCopyOptions opts;
      return copy(offset, count, part_number, from, opts);
    }

    int complete(uint64_t* expected_crc64) {
      return _client->complete_multipart_upload(_ctx, expected_crc64);
    }

    int abort() { return _client->abort_multipart_upload(_ctx); }

    operator bool() { return _ctx; }
  };

  MultipartUploadContext init_multipart_upload(std::string_view object) {
    void* ctx = nullptr;
    init_multipart_upload(object, &ctx);
    return {this, ctx};
  }

  // prefix + objects are to be deleted
  // no slash will be added after the prefix
  virtual int delete_objects(const std::vector<std::string_view>& objects,
                             std::string_view prefix = {}) = 0;

  virtual int delete_object(std::string_view obj) = 0;

  virtual int rename_object(std::string_view src_path,
                            std::string_view dst_path,
                            bool set_mime = false) = 0;

  virtual int put_symlink(std::string_view obj, std::string_view target) = 0;

  virtual int get_symlink(std::string_view obj, std::string& target) = 0;

  virtual int get_object_meta(std::string_view obj, ObjectMeta& meta) = 0;

  virtual void set_credentials(CredentialParameters&& credentials) = 0;

  // Extended multipart init with per-request options. The default
  // implementation keeps legacy derivations source-compatible: an empty
  // policy falls back to the two-argument interface; a present SSE policy
  // is rejected with -1/EOPNOTSUPP instead of being silently dropped.
  // `context` (when non-null) is always cleared and `opts.sse_response`
  // (when non-null) is always reset before returning.
  virtual int init_multipart_upload(std::string_view object, void** context,
                                    MultipartUploadOptions& opts);
};

Client* new_oss_client(const ClientOptions& opt, Authenticator* auth);

// if cache_ttl_secs is 0, no cache authenticator will be created.
Client* new_oss_client(const ClientOptions& opt, uint32_t cache_ttl_secs = 60,
                       CredentialParameters&& credentials = {});

Authenticator* new_basic_oss_authenticator(
    CredentialParameters&& credentials = {});

// if cache_ttl_secs is 0, the original authenticator will be returned.
Authenticator* new_cached_oss_authenticator(Authenticator* auth,
                                            uint32_t cache_ttl_secs = 60);

// one typical CustomAutheticator example
/*class CustomAuthenticator : public Authenticator {
  Authenticator* auth_ = nullptr;
 public:
  CustomAuthenticator(Authenticator* auth) : auth_(auth) {}

  ~CustomAuthenticator() { delete auth_; }

  virtual int sign(photon::net::http::Headers& headers,
                   const SignParameters& params) override {
    // add your own logic here
    return auth_->sign(headers, params);
  }

  virtual const CredentialParameters* get_credentials() override {
    // add your own logic here
    return auth_->get_credentials();
  }

  virtual void set_credentials(CredentialParameters&& credentials) override {
    auth_->set_credentials(std::move(credentials));
  }
};*/
}  // namespace objstore
}  // namespace photon
