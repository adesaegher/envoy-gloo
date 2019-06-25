#pragma once

#include "envoy/upstream/upstream.h"

#include "extensions/filters/http/common/empty_http_filter_config.h"
#include "extensions/filters/http/solo_well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace GcloudGfunc {

using Extensions::HttpFilters::Common::EmptyHttpFilterConfig;

/**
 * Config registration for the Gcloud Gfunc filter.
 */
class GcloudGfuncFilterConfigFactory : public EmptyHttpFilterConfig {
public:
  GcloudGfuncFilterConfigFactory()
      : EmptyHttpFilterConfig(SoloHttpFilterNames::get().GcloudGfunc) {}

  Upstream::ProtocolOptionsConfigConstSharedPtr
  createProtocolOptionsConfig(const Protobuf::Message &config) override;
  ProtobufTypes::MessagePtr createEmptyProtocolOptionsProto() override;
  ProtobufTypes::MessagePtr createEmptyRouteConfigProto() override;
  Router::RouteSpecificFilterConfigConstSharedPtr
  createRouteSpecificFilterConfig(
      const Protobuf::Message &,
      Server::Configuration::FactoryContext &) override;

private:
  Http::FilterFactoryCb
  createFilter(const std::string &stat_prefix,
               Server::Configuration::FactoryContext &context) override;
};

} // namespace GcloudGfunc
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
