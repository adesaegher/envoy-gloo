#pragma once

#include <string>

#include "envoy/server/filter_config.h"

#include "extensions/filters/http/common/empty_http_filter_config.h"
#include "extensions/filters/http/common/factory_base.h"
#include "extensions/filters/http/solo_well_known_names.h"

#include "api/envoy/config/filter/http/transformation/v2/transformation_filter.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Transformation {

using Common::EmptyHttpFilterConfig;

class TransformationFilterConfigFactory : public EmptyHttpFilterConfig {
public:
  TransformationFilterConfigFactory()
      : EmptyHttpFilterConfig(SoloHttpFilterNames::get().Transformation) {}

  ProtobufTypes::MessagePtr createEmptyRouteConfigProto() override;
  Router::RouteSpecificFilterConfigConstSharedPtr
  createRouteSpecificFilterConfig(
      const Protobuf::Message &,
      Server::Configuration::FactoryContext &) override;
  Http::FilterFactoryCb
  createFilter(const std::string &stat_prefix,
               Server::Configuration::FactoryContext &context) override;
};

} // namespace Transformation
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
