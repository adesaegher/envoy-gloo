#include "extensions/filters/http/gfunction/gfunction_filter_config_factory.h"

#include "envoy/registry/registry.h"

#include "extensions/filters/http/gfunction/gfunction_filter.h"

#include "api/envoy/config/filter/http/gfunction/v2/gfunction.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace GcloudGfunc {

Http::FilterFactoryCb GcloudGfuncFilterConfigFactory::createFilter(
    const std::string &, Server::Configuration::FactoryContext &context) {
  return [&context](Http::FilterChainFactoryCallbacks &callbacks) -> void {
    auto filter = new GcloudGfuncFilter(context.clusterManager());
//                                      context.dispatcher().timeSource());
    callbacks.addStreamDecoderFilter(
        Http::StreamDecoderFilterSharedPtr{filter});
  };
}

Upstream::ProtocolOptionsConfigConstSharedPtr
GcloudGfuncFilterConfigFactory::createProtocolOptionsConfig(
    const Protobuf::Message &config) {
  const auto &proto_config =
      dynamic_cast<const envoy::config::filter::http::gfunction::v2::
                       GcloudGfuncProtocolExtension &>(config);
  return std::make_shared<const GcloudGfuncProtocolExtensionConfig>(proto_config);
}

ProtobufTypes::MessagePtr
GcloudGfuncFilterConfigFactory::createEmptyProtocolOptionsProto() {
  return std::make_unique<envoy::config::filter::http::gfunction::v2::
                              GcloudGfuncProtocolExtension>();
}

ProtobufTypes::MessagePtr
GcloudGfuncFilterConfigFactory::createEmptyRouteConfigProto() {
  return std::make_unique<
      envoy::config::filter::http::gfunction::v2::GcloudGfuncPerRoute>();
}

Router::RouteSpecificFilterConfigConstSharedPtr
GcloudGfuncFilterConfigFactory::createRouteSpecificFilterConfig(
    const Protobuf::Message &config, Server::Configuration::FactoryContext &) {
  const auto &proto_config = dynamic_cast<
      const envoy::config::filter::http::gfunction::v2::GcloudGfuncPerRoute &>(
      config);
  return std::make_shared<const GcloudGfuncRouteConfig>(proto_config);
}

/**
 * Static registration for the Gcloud Gfunc filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<
    GcloudGfuncFilterConfigFactory,
    Server::Configuration::NamedHttpFilterConfigFactory>
    register_;

} // namespace GcloudGfunc
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
