// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "sandbox/win/src/acl.h"

#include <windows.h>
#include <optional>

#include "base/notreached.h"

namespace sandbox {

namespace {

constexpr DWORD kMediumLowRid = SECURITY_MANDATORY_MEDIUM_RID - 2048;
constexpr DWORD kBelowLowRid = SECURITY_MANDATORY_LOW_RID - 2048;

}  

std::optional<DWORD> GetIntegrityLevelRid(IntegrityLevel integrity_level) {
  switch (integrity_level) {
    case INTEGRITY_LEVEL_SYSTEM:
      return SECURITY_MANDATORY_SYSTEM_RID;
    case INTEGRITY_LEVEL_HIGH:
      return SECURITY_MANDATORY_HIGH_RID;
    case INTEGRITY_LEVEL_MEDIUM:
      return SECURITY_MANDATORY_MEDIUM_RID;
    case INTEGRITY_LEVEL_MEDIUM_LOW:
      return kMediumLowRid;
    case INTEGRITY_LEVEL_LOW:
      return SECURITY_MANDATORY_LOW_RID;
    case INTEGRITY_LEVEL_BELOW_LOW:
      return kBelowLowRid;
    case INTEGRITY_LEVEL_UNTRUSTED:
      return SECURITY_MANDATORY_UNTRUSTED_RID;
    case INTEGRITY_LEVEL_LAST:
      return std::nullopt;
  }

  NOTREACHED();
  return std::nullopt;
}

DWORD SetObjectIntegrityLabel(HANDLE handle,
                              base::win::SecurityObjectType object_type,
                              DWORD mandatory_policy,
                              IntegrityLevel integrity_level) {
  const std::optional<DWORD> rid = GetIntegrityLevelRid(integrity_level);
  if (!rid) {
    return ERROR_INVALID_SID;
  }

  base::win::SecurityDescriptor sd;
  if (!sd.SetMandatoryLabel(*rid, 0, mandatory_policy)) {
    return ::GetLastError();
  }

  if (!sd.WriteToHandle(handle, object_type, LABEL_SECURITY_INFORMATION)) {
    return ::GetLastError();
  }

  return ERROR_SUCCESS;
}

}  // namespace sandbox
