/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "wallpaper_service_cb_proxy.h"

#include "hilog_wrapper.h"

namespace OHOS {
namespace WallpaperMgrService {
int32_t WallpaperServiceCbProxy::OnCall(const int32_t wallpaperType)
{
    HILOG_INFO("WallpaperServiceCbProxy::OnCall start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        HILOG_ERROR("Failed to write parcelable ");
        return -1;
    }
    if (!data.WriteInt32(wallpaperType)) {
        HILOG_ERROR("Failed to WriteInt32 ");
        return -1;
    }
    HILOG_INFO("WallpaperServiceCbProxy::Remote()->SendRequest");
    Remote()->SendRequest(ONCALL, data, reply, option);
    return 0;
}

int32_t WallpaperServiceCbProxy::OnOffsetCall(const int32_t xOffset, const int32_t yOffset)
{
    HILOG_INFO("WallpaperServiceCbProxy::OnOffsetCall start");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        HILOG_ERROR("Failed to write parcelable ");
        return E_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(xOffset)) {
        HILOG_ERROR("Failed to WriteInt32 xOffset");
        return E_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(yOffset)) {
        HILOG_ERROR("Failed to WriteInt32 yOffset");
        return E_WRITE_PARCEL_ERROR;
    }
    int32_t ret = Remote()->SendRequest(ON_OFFSET_CALL, data, reply, option);
    if (ret != ERR_NONE) {
        HILOG_ERROR("OnLiveCall, rpc error code = %{public}d", ret);
        return E_DEAL_FAILED;
    }
    return ret;
}
} // namespace WallpaperMgrService
} // namespace OHOS