//===--- ClangTidyCheck.cpp - clang-tidy ------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ClangTidyCheck.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/YAMLParser.h"

namespace clang {
namespace tidy {

char MissingOptionError::ID;
char UnparseableEnumOptionError::ID;
char UnparseableIntegerOptionError::ID;

std::string MissingOptionError::message() const {
  llvm::SmallString<128> Buffer({"option not found '", OptionName, "'"});
  return std::string(Buffer);
}

std::string UnparseableEnumOptionError::message() const {
  llvm::SmallString<256> Buffer({"invalid configuration value '", LookupValue,
                                 "' for option '", LookupName, "'"});
  if (SuggestedValue)
    Buffer.append({"; did you mean '", *SuggestedValue, "'?"});
  return std::string(Buffer);
}

std::string UnparseableIntegerOptionError::message() const {
  llvm::SmallString<256> Buffer({"invalid configuration value '", LookupValue,
                                 "' for option '", LookupName, "'; expected ",
                                 (IsBoolean ? "a bool" : "an integer value")});
  return std::string(Buffer);
}

ClangTidyCheck::ClangTidyCheck(StringRef CheckName, ClangTidyContext *Context)
    : CheckName(CheckName), Context(Context),
      Options(CheckName, Context->getOptions().CheckOptions, Context) {
  assert(Context != nullptr);
  assert(!CheckName.empty());
}

DiagnosticBuilder ClangTidyCheck::diag(SourceLocation Loc, StringRef Message,
                                       DiagnosticIDs::Level Level) {
  return Context->diag(CheckName, Loc, Message, Level);
}

DiagnosticBuilder ClangTidyCheck::diag(StringRef Message,
                                       DiagnosticIDs::Level Level) {
  return Context->diag(CheckName, Message, Level);
}

DiagnosticBuilder
ClangTidyCheck::configurationDiag(StringRef Description,
                                  DiagnosticIDs::Level Level) {
  return Context->configurationDiag(Description, Level);
}

void ClangTidyCheck::run(const ast_matchers::MatchFinder::MatchResult &Result) {
  // For historical reasons, checks don't implement the MatchFinder run()
  // callback directly. We keep the run()/check() distinction to avoid interface
  // churn, and to allow us to add cross-cutting logic in the future.
  check(Result);
}

ClangTidyCheck::OptionsView::OptionsView(
    StringRef CheckName, const ClangTidyOptions::OptionMap &CheckOptions,
    ClangTidyContext *Context)
    : NamePrefix(CheckName.str() + "."), CheckOptions(CheckOptions),
      Context(Context) {}

llvm::Expected<std::string>
ClangTidyCheck::OptionsView::get(StringRef LocalName) const {
  const auto &Iter = CheckOptions.find(NamePrefix + LocalName.str());
  if (Iter != CheckOptions.end())
    return Iter->getValue().Value;
  return llvm::make_error<MissingOptionError>((NamePrefix + LocalName).str());
}

static ClangTidyOptions::OptionMap::const_iterator
findPriorityOption(const ClangTidyOptions::OptionMap &Options, StringRef NamePrefix,
          StringRef LocalName) {
  auto IterLocal = Options.find((NamePrefix + LocalName).str());
  auto IterGlobal = Options.find(LocalName.str());
  if (IterLocal == Options.end())
    return IterGlobal;
  if (IterGlobal == Options.end())
    return IterLocal;
  if (IterLocal->getValue().Priority >= IterGlobal->getValue().Priority)
    return IterLocal;
  return IterGlobal;
}

llvm::Expected<std::string>
ClangTidyCheck::OptionsView::getLocalOrGlobal(StringRef LocalName) const {
  auto Iter = findPriorityOption(CheckOptions, NamePrefix, LocalName);
  if (Iter != CheckOptions.end())
    return Iter->getValue().Value;
  return llvm::make_error<MissingOptionError>((NamePrefix + LocalName).str());
}

static llvm::Expected<bool> getAsBool(StringRef Value,
                                      const llvm::Twine &LookupName) {

  if (llvm::Optional<bool> Parsed = llvm::yaml::parseBool(Value))
    return *Parsed;
  // To maintain backwards compatability, we support parsing numbers as
  // booleans, even though its not supported in YAML.
  long long Number;
  if (!Value.getAsInteger(10, Number))
    return Number != 0;
  return llvm::make_error<UnparseableIntegerOptionError>(LookupName.str(),
                                                         Value.str(), true);
}

template <>
llvm::Expected<bool>
ClangTidyCheck::OptionsView::get<bool>(StringRef LocalName) const {
  llvm::Expected<std::string> ValueOr = get(LocalName);
  if (ValueOr)
    return getAsBool(*ValueOr, NamePrefix + LocalName);
  return ValueOr.takeError();
}

template <>
bool ClangTidyCheck::OptionsView::get<bool>(StringRef LocalName,
                                            bool Default) const {
  llvm::Expected<bool> ValueOr = get<bool>(LocalName);
  if (ValueOr)
    return *ValueOr;
  reportOptionParsingError(ValueOr.takeError());
  return Default;
}

template <>
llvm::Expected<bool>
ClangTidyCheck::OptionsView::getLocalOrGlobal<bool>(StringRef LocalName) const {
  auto Iter = findPriorityOption(CheckOptions, NamePrefix, LocalName);
  if (Iter != CheckOptions.end())
    return getAsBool(Iter->getValue().Value, Iter->getKey());
  return llvm::make_error<MissingOptionError>((NamePrefix + LocalName).str());
}

template <>
bool ClangTidyCheck::OptionsView::getLocalOrGlobal<bool>(StringRef LocalName,
                                                         bool Default) const {
  llvm::Expected<bool> ValueOr = getLocalOrGlobal<bool>(LocalName);
  if (ValueOr)
    return *ValueOr;
  reportOptionParsingError(ValueOr.takeError());
  return Default;
}

void ClangTidyCheck::OptionsView::store(ClangTidyOptions::OptionMap &Options,
                                        StringRef LocalName,
                                        StringRef Value) const {
  Options[NamePrefix + LocalName.str()] = Value;
}

void ClangTidyCheck::OptionsView::storeInt(ClangTidyOptions::OptionMap &Options,
                                           StringRef LocalName,
                                           int64_t Value) const {
  store(Options, LocalName, llvm::itostr(Value));
}

template <>
void ClangTidyCheck::OptionsView::store<bool>(
    ClangTidyOptions::OptionMap &Options, StringRef LocalName,
    bool Value) const {
  store(Options, LocalName, Value ? StringRef("true") : StringRef("false"));
}

llvm::Expected<int64_t> ClangTidyCheck::OptionsView::getEnumInt(
    StringRef LocalName, ArrayRef<NameAndValue> Mapping, bool CheckGlobal,
    bool IgnoreCase) const {
  auto Iter = CheckGlobal
                  ? findPriorityOption(CheckOptions, NamePrefix, LocalName)
                  : CheckOptions.find((NamePrefix + LocalName).str());
  if (Iter == CheckOptions.end())
    return llvm::make_error<MissingOptionError>((NamePrefix + LocalName).str());

  StringRef Value = Iter->getValue().Value;
  StringRef Closest;
  unsigned EditDistance = -1;
  for (const auto &NameAndEnum : Mapping) {
    if (IgnoreCase) {
      if (Value.equals_lower(NameAndEnum.second))
        return NameAndEnum.first;
    } else if (Value.equals(NameAndEnum.second)) {
      return NameAndEnum.first;
    } else if (Value.equals_lower(NameAndEnum.second)) {
      Closest = NameAndEnum.second;
      EditDistance = 0;
      continue;
    }
    unsigned Distance = Value.edit_distance(NameAndEnum.second);
    if (Distance < EditDistance) {
      EditDistance = Distance;
      Closest = NameAndEnum.second;
    }
  }
  if (EditDistance < 3)
    return llvm::make_error<UnparseableEnumOptionError>(
        Iter->getKey().str(), Iter->getValue().Value, Closest.str());
  return llvm::make_error<UnparseableEnumOptionError>(Iter->getKey().str(),
                                                      Iter->getValue().Value);
}

void ClangTidyCheck::OptionsView::reportOptionParsingError(
    llvm::Error &&Err) const {
  if (auto RemainingErrors =
          llvm::handleErrors(std::move(Err), [](const MissingOptionError &) {}))
    Context->configurationDiag(llvm::toString(std::move(RemainingErrors)));
}

template <>
Optional<std::string> ClangTidyCheck::OptionsView::getOptional<std::string>(
    StringRef LocalName) const {
  if (auto ValueOr = get(LocalName))
    return *ValueOr;
  else
    consumeError(ValueOr.takeError());
  return llvm::None;
}

template <>
Optional<std::string>
ClangTidyCheck::OptionsView::getOptionalLocalOrGlobal<std::string>(
    StringRef LocalName) const {
  if (auto ValueOr = getLocalOrGlobal(LocalName))
    return *ValueOr;
  else
    consumeError(ValueOr.takeError());
  return llvm::None;
}

} // namespace tidy
} // namespace clang