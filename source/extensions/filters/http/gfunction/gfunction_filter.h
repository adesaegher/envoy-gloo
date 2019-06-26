#pragma once

#include <map>
#include <string>

#include "envoy/http/filter.h"
#include "envoy/upstream/cluster_manager.h"

//#include "extensions/filters/http/gfunction/gcloud_authenticator.h"
#include "extensions/filters/http/gfunction/config.h"

#include "api/envoy/config/filter/http/gfunction/v2/gfunction.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace GcloudGfunc {

/*
 * A filter to make calls to Gcloud Gfunc. Note that as a functional filter,
 * it expects retrieveFunction to be called before decodeHeaders.
 */
class GcloudGfuncFilter : public Http::StreamDecoderFilter {
public:
  GcloudGfuncFilter(Upstream::ClusterManager &cluster_manager
                  );
  ~GcloudGfuncFilter();

  // Http::StreamFilterBase
  void onDestroy() override {}

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::HeaderMap &, bool) override;
  Http::FilterDataStatus decodeData(Buffer::Instance &, bool) override;
  Http::FilterTrailersStatus decodeTrailers(Http::HeaderMap &) override;
  void setDecoderFilterCallbacks(
      Http::StreamDecoderFilterCallbacks &decoder_callbacks) override {
    decoder_callbacks_ = &decoder_callbacks;
  }

private:
//  static const HeaderList HeadersToSign;

  void handleDefaultBody();

  void gfuncfy();
  static std::string functionUrlPath(const std::string &url);
  void cleanup();

  Http::HeaderMap *request_headers_{};
//  GcloudAuthenticator gcloud_authenticator_;

  Http::StreamDecoderFilterCallbacks *decoder_callbacks_{};

  Upstream::ClusterManager &cluster_manager_;
  std::shared_ptr<const GcloudGfuncProtocolExtensionConfig> protocol_options_;

  Router::RouteConstSharedPtr route_;
  const GcloudGfuncRouteConfig *function_on_route_{};
  bool has_body_{};
};

} // namespace GcloudGfunc
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
