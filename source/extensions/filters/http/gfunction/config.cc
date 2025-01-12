#include "extensions/filters/http/gfunction/config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace GcloudGfunc {

GcloudGfuncRouteConfig::GcloudGfuncRouteConfig(
    const envoy::config::filter::http::gfunction::v2::GcloudGfuncPerRoute
        &protoconfig)
    : name_(protoconfig.name()), url_(protoconfig.url()) {

  if (protoconfig.has_empty_body_override()) {
    default_body_ = protoconfig.empty_body_override().value();
  }
}

} // namespace GcloudGfunc
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
