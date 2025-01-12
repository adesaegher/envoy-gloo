#pragma once

#include <map>

#include "envoy/buffer/buffer.h"
#include "envoy/http/header_map.h"

// clang-format off
#include "json.hpp"
#include "inja.hpp"
// clang-format on

#include "api/envoy/config/filter/http/transformation/v2/transformation_filter.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Transformation {

class ExtractorUtil {
public:
  static std::string
  extract(const envoy::api::v2::filter::http::Extraction &extractor,
          const Http::HeaderMap &header_map);
};

class TransformerInstance {
public:
  TransformerInstance(const Http::HeaderMap &header_map,
                      const std::map<std::string, std::string> &extractions,
                      const nlohmann::json &context);
  // header_value(name)
  // extracted_value(name, index)
  nlohmann::json header_callback(inja::Parsed::Arguments args,
                                 nlohmann::json data);

  nlohmann::json extracted_callback(inja::Parsed::Arguments args,
                                    nlohmann::json data);

  std::string render(const std::string &input);

  void useDotNotation() {
    env_.set_element_notation(inja::ElementNotation::Dot);
  }

private:
  inja::Environment env_;
  const Http::HeaderMap &header_map_;
  const std::map<std::string, std::string> &extractions_;
  const nlohmann::json &context_;
};

class Transformer {
public:
  Transformer(const envoy::api::v2::filter::http::TransformationTemplate
                  &transformation);
  ~Transformer();

  void transform(Http::HeaderMap &map, Buffer::Instance &body);

private:
  /*
    TransformerImpl& impl() { return reinterpret_cast<TransformerImpl&>(impl_);
    } const TransformerImpl& impl() const { return reinterpret_cast<const
    TransformerImpl &>(impl_); }

    static const size_t TransformerImplSize = 464;
    static const size_t TransformerImplAlign = 8;

    std::aligned_storage<TransformerImplSize, TransformerImplAlign>::type impl_;
  */
  const envoy::api::v2::filter::http::TransformationTemplate &transformation_;
};

} // namespace Transformation
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
