#include "extensions/filters/http/gfunction/gfunction_filter.h"

#include <algorithm>
#include <list>
#include <string>
#include <vector>

#include "envoy/http/header_map.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/empty_string.h"
#include "common/common/hex.h"
#include "common/common/utility.h"
#include "common/http/headers.h"
#include "common/http/solo_filter_utility.h"
#include "common/http/utility.h"
#include "common/singleton/const_singleton.h"

#include "extensions/filters/http/solo_well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace GcloudGfunc {

struct RcDetailsValues {
  // The jwt_authn filter rejected the request
  const std::string FunctionNotFound = "gfunction_function_not_found";
};
typedef ConstSingleton<RcDetailsValues> RcDetails;

class GcloudGfuncHeaderValues {
public:
  const Http::LowerCaseString InvocationType{"x-amz-invocation-type"};
  const std::string InvocationTypeEvent{"Event"};
  const std::string InvocationTypeRequestResponse{"RequestResponse"};
  const Http::LowerCaseString LogType{"x-amz-log-type"};
  const std::string LogNone{"None"};
  const Http::LowerCaseString HostHead{"x-amz-log-type"};
};

typedef ConstSingleton<GcloudGfuncHeaderValues> GcloudGfuncHeaderNames;

//const HeaderList GcloudGfuncFilter::HeadersToSign =
//    GcloudAuthenticator::createHeaderToSign(
//        {GcloudGfuncHeaderNames::get().InvocationType,
//         GcloudGfuncHeaderNames::get().LogType, Http::Headers::get().HostLegacy,
//         Http::Headers::get().ContentType});

GcloudGfuncFilter::GcloudGfuncFilter(Upstream::ClusterManager &cluster_manager
                                 )
//                                 TimeSource &time_source)
//    : gcloud_authenticator_(time_source), cluster_manager_(cluster_manager) {}
    : cluster_manager_(cluster_manager) {}

GcloudGfuncFilter::~GcloudGfuncFilter() {}

std::string GcloudGfuncFilter::functionUrlPath(const std::string &url) {

  std::stringstream val;
  absl::string_view host;
  absl::string_view path;
  Http::Utility::extractHostPathFromUri(url, host, path);
  val << path;
  return val.str();

}

Http::FilterHeadersStatus
GcloudGfuncFilter::decodeHeaders(Http::HeaderMap &headers, bool end_stream) {

  protocol_options_ = Http::SoloFilterUtility::resolveProtocolOptions<
      const GcloudGfuncProtocolExtensionConfig>(
      SoloHttpFilterNames::get().GcloudGfunc, decoder_callbacks_,
      cluster_manager_);
  if (!protocol_options_) {
    return Http::FilterHeadersStatus::Continue;
  }

  route_ = decoder_callbacks_->route();
  // great! this is an gcloud cluster. get the function information:
  function_on_route_ =
      Http::SoloFilterUtility::resolvePerFilterConfig<GcloudGfuncRouteConfig>(
          SoloHttpFilterNames::get().GcloudGfunc, route_);

  if (!function_on_route_) {
    decoder_callbacks_->sendLocalReply(Http::Code::NotFound,
                                       "no function present for Gcloud upstream",
                                       nullptr, absl::nullopt, RcDetails::get().FunctionNotFound);
    return Http::FilterHeadersStatus::StopIteration;
  }

//  gcloud_authenticator_.init(&protocol_options_->accessKey(),
//                          &protocol_options_->secretKey());
  request_headers_ = &headers;

  request_headers_->insertMethod().value().setReference(
      Http::Headers::get().MethodValues.Post);

  request_headers_->insertPath().value(functionUrlPath(
      function_on_route_->url()));

  if (end_stream) {
    gfuncfy();
    return Http::FilterHeadersStatus::Continue;
  }

  return Http::FilterHeadersStatus::StopIteration;
}

Http::FilterDataStatus GcloudGfuncFilter::decodeData(Buffer::Instance &data,
                                                   bool end_stream) {
  if (!function_on_route_) {
    return Http::FilterDataStatus::Continue;
  }

  if (data.length() != 0) {
    has_body_ = true;
  }

//  gcloud_authenticator_.updatePayloadHash(data);

  if (end_stream) {
    gfuncfy();
    return Http::FilterDataStatus::Continue;
  }

  return Http::FilterDataStatus::StopIterationAndBuffer;
}

Http::FilterTrailersStatus GcloudGfuncFilter::decodeTrailers(Http::HeaderMap &) {
  if (function_on_route_ != nullptr) {
    gfuncfy();
  }

  return Http::FilterTrailersStatus::Continue;
}

void GcloudGfuncFilter::gfuncfy() {

  handleDefaultBody();

  request_headers_->addReference(GcloudGfuncHeaderNames::get().LogType,
                                 GcloudGfuncHeaderNames::get().LogNone);
  request_headers_->insertHost().value(protocol_options_->host());

//  gcloud_authenticator_.sign(request_headers_, HeadersToSign,
//                          protocol_options_->region());
  cleanup();
}

void GcloudGfuncFilter::handleDefaultBody() {
  if ((!has_body_) && function_on_route_->defaultBody()) {
    Buffer::OwnedImpl data(function_on_route_->defaultBody().value());

    request_headers_->insertContentType().value().setReference(
        Http::Headers::get().ContentTypeValues.Json);
    request_headers_->insertContentLength().value(data.length());
//    gcloud_authenticator_.updatePayloadHash(data);
    decoder_callbacks_->addDecodedData(data, false);
  }
}

void GcloudGfuncFilter::cleanup() {
  request_headers_ = nullptr;
  function_on_route_ = nullptr;
  protocol_options_.reset();
}

} // namespace GcloudGfunc
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
