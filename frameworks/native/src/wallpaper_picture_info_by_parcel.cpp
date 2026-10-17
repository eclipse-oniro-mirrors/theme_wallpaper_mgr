/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "wallpaper_picture_info_by_parcel.h"

#include <fcntl.h>
#include <vector>

#include "hilog_wrapper.h"

namespace OHOS::WallpaperMgrService {
constexpr int32_t VECTOR_MAX_SIZE = 6;
constexpr int32_t VECTOR_MIN_SIZE = 0;
WallpaperPictureInfoByParcel::WallpaperPictureInfoByParcel()
{
}

bool WallpaperPictureInfoByParcel::Marshalling(Parcel &parcel) const
{
    bool status = true;
    auto *messageParcel = static_cast<MessageParcel *>(&parcel);
    if (messageParcel == nullptr) {
        HILOG_ERROR("parcel is not MessageParcel, cannot marshal fd.");
        return false;
    }
    status &= parcel.WriteInt32(wallpaperPictureInfo_.size());
    for (const auto &wallpaperInfo : wallpaperPictureInfo_) {
        status &= parcel.WriteInt32(static_cast<int32_t>(wallpaperInfo.foldState));
        status &= parcel.WriteInt32(static_cast<int32_t>(wallpaperInfo.rotateState));
        status &= messageParcel->WriteFileDescriptor(wallpaperInfo.fd);
        status &= parcel.WriteInt32(wallpaperInfo.length);
        if (!status) {
            HILOG_ERROR("Marshalling failed.");
            break;
        }
    }
    return status;
}

WallpaperPictureInfoByParcel *WallpaperPictureInfoByParcel::Unmarshalling(Parcel &parcel)
{
    WallpaperPictureInfoByParcel *obj = new (std::nothrow) WallpaperPictureInfoByParcel();
    if (obj == nullptr) {
        HILOG_ERROR("obj is nullptr");
        return nullptr;
    }
    int32_t vectorSize = parcel.ReadInt32();
    if (vectorSize > VECTOR_MAX_SIZE || vectorSize < VECTOR_MIN_SIZE) {
        HILOG_ERROR("More than maxNum 6 or less than minNum 0 of wallpaper pictures, size:%{public}d", vectorSize);
        delete obj;
        return nullptr;
    }
    auto *messageParcel = static_cast<MessageParcel *>(&parcel);
    if (messageParcel == nullptr) {
        HILOG_ERROR("parcel is not MessageParcel, cannot unmarshal fd.");
        delete obj;
        return nullptr;
    }
    for (int32_t i = 0; i < vectorSize; i++) {
        WallpaperPictureInfo wallpaperInfo;
        if (!ReadOneWallpaperInfo(parcel, *messageParcel, wallpaperInfo)) {
            CloseWallpaperInfoFd(obj->wallpaperPictureInfo_);
            delete obj;
            return nullptr;
        }
        obj->wallpaperPictureInfo_.push_back(wallpaperInfo);
    }
    return obj;
}

bool WallpaperPictureInfoByParcel::ReadFoldState(int32_t value, FoldState &out)
{
    switch (value) {
        case static_cast<int32_t>(FoldState::NORMAL):
            out = NORMAL;
            return true;
        case static_cast<int32_t>(FoldState::UNFOLD_1):
            out = UNFOLD_1;
            return true;
        case static_cast<int32_t>(FoldState::UNFOLD_2):
            out = UNFOLD_2;
            return true;
        default:
            return false;
    }
}

bool WallpaperPictureInfoByParcel::ReadRotateState(int32_t value, RotateState &out)
{
    switch (value) {
        case static_cast<int32_t>(RotateState::PORT):
            out = PORT;
            return true;
        case static_cast<int32_t>(RotateState::LAND):
            out = LAND;
            return true;
        default:
            return false;
    }
}

bool WallpaperPictureInfoByParcel::ReadOneWallpaperInfo(
    Parcel &parcel, MessageParcel &messageParcel, WallpaperPictureInfo &info)
{
    int32_t foldStateValue = parcel.ReadInt32();
    int32_t rotateStateValue = parcel.ReadInt32();
    if (!ReadFoldState(foldStateValue, info.foldState)) {
        HILOG_ERROR("invalid foldState:%{public}d", foldStateValue);
        return false;
    }
    if (!ReadRotateState(rotateStateValue, info.rotateState)) {
        HILOG_ERROR("invalid rotateState:%{public}d", rotateStateValue);
        return false;
    }
    info.fd = messageParcel.ReadFileDescriptor();
    if (info.fd < 0) {
        HILOG_ERROR("ReadFileDescriptor fail.");
        return false;
    }
    info.length = parcel.ReadInt32();
    return true;
}

void WallpaperPictureInfoByParcel::CloseWallpaperInfoFd(std::vector<WallpaperPictureInfo> &wallpaperPictureInfos)
{
    for (auto &wallpaperInfo : wallpaperPictureInfos) {
        if (wallpaperInfo.fd >= 0) {
            fdsan_exchange_owner_tag(wallpaperInfo.fd, 0, WP_DOMAIN);
            fdsan_close_with_tag(wallpaperInfo.fd, WP_DOMAIN);
            wallpaperInfo.fd = -1;
        }
    }
}

} // namespace OHOS::WallpaperMgrService