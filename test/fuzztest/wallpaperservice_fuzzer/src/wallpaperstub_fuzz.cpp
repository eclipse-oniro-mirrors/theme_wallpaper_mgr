/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>

#include "message_parcel.h"
#include "wallpaper_service.h"
#include "wallpaperstub_fuzzer.h"

using namespace OHOS::WallpaperMgrService;
namespace OHOS {
const std::u16string WALLPAPERSERVICES_INTERFACE_TOKEN = u"OHOS.WallpaperMgrService.IWallpaperService";

void FuzzTestRemoteRequest(FuzzedDataProvider &provider)
{
    MessageParcel data;
    data.WriteInterfaceToken(WALLPAPERSERVICES_INTERFACE_TOKEN);
    std::vector<uint8_t> remaining_data = provider.ConsumeRemainingBytes<uint8_t>();
    data.WriteBuffer(static_cast<void *>(remaining_data.data()), remaining_data.size());
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    std::shared_ptr<WallpaperService> wallpaperService = std::make_shared<WallpaperService>();
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    wallpaperService->OnRemoteRequest(code, data, reply, option);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::FuzzTestRemoteRequest(provider);
    return 0;
}