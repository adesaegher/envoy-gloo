#pragma once

#include <map>
#include <string>

#include "envoy/http/filter.h"
#include "envoy/upstream/cluster_manager.h"

#include "absl/types/optional.h"
#include "api/envoy/config/filter/http/gfunction/v2/gfunction.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace GcloudGfunc {

class GcloudGfuncRouteConfig : public Router::RouteSpecificFilterConfig {
public:
  GcloudGfuncRouteConfig(
      const envoy::config::filter::http::gfunction::v2::GcloudGfuncPerRoute
          &protoconfig);

  const std::string &name() const { return name_; }
  const std::string &url() const { return url_; }
  const absl::optional<std::string> &defaultBody() const {
    return default_body_;
  }

private:
  std::string name_;
  std::string url_;
  absl::optional<std::string> default_body_;
};

class GcloudGfuncProtocolExtensionConfig
    : public Upstream::ProtocolOptionsConfig {
public:
  GcloudGfuncProtocolExtensionConfig(
      const envoy::config::filter::http::gfunction::v2::
          GcloudGfuncProtocolExtension &protoconfig)
      : region_(protoconfig.region()),
        access_key_(protoconfig.access_key()),
        json_key_(protoconfig.json_key()) {}

  const std::string &region() const { return region_; }
  const std::string &accessKey() const { return access_key_; }
  const std::string &jsonKey() const { return json_key_; }

private:
  std::string region_;
  std::string access_key_;
  std::string json_key_;
};

} // namespace GcloudGfunc
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
