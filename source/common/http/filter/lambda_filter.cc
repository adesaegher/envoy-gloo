#include "common/http/filter/lambda_filter.h"

#include <algorithm>
#include <list>
#include <string>
#include <vector>

#include "envoy/http/header_map.h"

#include "common/common/empty_string.h"
#include "common/common/hex.h"
#include "common/common/utility.h"
#include "common/http/filter_utility.h"
#include "common/http/solo_filter_utility.h"
#include "common/http/utility.h"

#include "server/config/network/http_connection_manager.h"

namespace Envoy {
namespace Http {

LambdaFilter::LambdaFilter(Http::FunctionRetrieverSharedPtr retreiver,
                           Server::Configuration::FactoryContext &ctx,
                           const std::string &name,
                           LambdaFilterConfigSharedPtr config)
    : FunctionalFilterBase(ctx, name), config_(config),
      functionRetriever_(retreiver), cm_(ctx.clusterManager()) {}

LambdaFilter::~LambdaFilter() { cleanup(); }

std::string LambdaFilter::functionUrlPath() {

  std::stringstream val;
  val << "/2015-03-31/functions/" << (*currentFunction_.name_)
      << "/invocations";
  if ((currentFunction_.qualifier_ != nullptr) &&
      (!currentFunction_.qualifier_->empty())) {
    val << "?Qualifier=" << (*currentFunction_.qualifier_);
  }
  return val.str();
}

Envoy::Http::FilterHeadersStatus
LambdaFilter::functionDecodeHeaders(Envoy::Http::HeaderMap &headers,
                                    bool end_stream) {

  auto optionalFunction = functionRetriever_->getFunction(*this);
  if (!optionalFunction.valid()) {
    // This is ours to handle - return error to the user
    Utility::sendLocalReply(*decoder_callbacks_, is_reset_,
                            Code::InternalServerError,
                            "AWS Function not available");
    // Doing continue after a local reply is a bad thing...
    return Envoy::Http::FilterHeadersStatus::StopIteration;
  }
  active_ = true;
  currentFunction_ = std::move(optionalFunction.value());
  // placement new
  new (&aws_authenticator_) AwsAuthenticator(*currentFunction_.access_key_,
                                             *currentFunction_.secret_key_);
  request_headers_ = &headers;

  request_headers_->insertMethod().value().setReference(
      Envoy::Http::Headers::get().MethodValues.Post);

  //  request_headers_->removeContentLength();
  request_headers_->insertPath().value(functionUrlPath());

  ENVOY_LOG(debug, "decodeHeaders called end = {}", end_stream);
  if (end_stream) {
    lambdafy();
    return Envoy::Http::FilterHeadersStatus::Continue;
  }

  return Envoy::Http::FilterHeadersStatus::StopIteration;
}

Envoy::Http::FilterDataStatus
LambdaFilter::functionDecodeData(Envoy::Buffer::Instance &data,
                                 bool end_stream) {
  if (!active_) {
    return Envoy::Http::FilterDataStatus::Continue;
  }
  aws_authenticator_.updatePayloadHash(data);

  if (end_stream) {

    lambdafy();
    // Authorization: AWS4-HMAC-SHA256
    // Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request,
    // SignedHeaders=content-type;host;x-amz-date,
    // Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7
    // add header ?!
    // get stream id
    return Envoy::Http::FilterDataStatus::Continue;
  }

  return Envoy::Http::FilterDataStatus::StopIterationAndBuffer;
}

void LambdaFilter::lambdafy() {
  std::list<Envoy::Http::LowerCaseString> headers;

  headers.push_back(Envoy::Http::LowerCaseString("x-amz-invocation-type"));
  if (currentFunction_.async_) {
    request_headers_->addCopy(
        Envoy::Http::LowerCaseString("x-amz-invocation-type"),
        std::string("Event"));
  } else {
    request_headers_->addCopy(
        Envoy::Http::LowerCaseString("x-amz-invocation-type"),
        std::string("RequestResponse"));
  }

  //  headers.push_back(Envoy::Http::LowerCaseString("x-amz-client-context"));
  //  request_headers_->addCopy(Envoy::Http::LowerCaseString("x-amz-client-context"),
  //  std::string(""));

  headers.push_back(Envoy::Http::LowerCaseString("x-amz-log-type"));
  request_headers_->addCopy(Envoy::Http::LowerCaseString("x-amz-log-type"),
                            std::string("None"));

  headers.push_back(Envoy::Http::LowerCaseString("host"));
  request_headers_->insertHost().value(*currentFunction_.host_);

  headers.push_back(Envoy::Http::LowerCaseString("content-type"));

  aws_authenticator_.sign(request_headers_, std::move(headers),
                          *currentFunction_.region_);
  cleanup();
}

Envoy::Http::FilterTrailersStatus
LambdaFilter::functionDecodeTrailers(Envoy::Http::HeaderMap &) {
  if (active_) {
    lambdafy();
  }

  return Envoy::Http::FilterTrailersStatus::Continue;
}

void LambdaFilter::cleanup() {
  request_headers_ = nullptr;
  if (active_) {
    active_ = false;
    aws_authenticator_.~AwsAuthenticator();
  }
}

} // namespace Http
} // namespace Envoy
