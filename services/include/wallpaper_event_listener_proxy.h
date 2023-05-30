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

#ifndef WALLPAPER_EVENT_LISTENER_PROXY_H
#define WALLPAPER_EVENT_LISTENER_PROXY_H

#include <cstdint>
#include <vector>
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "refbase.h"
#include "wallpaper_manager_common_info.h"
#include "iwallpaper_event_listener.h"

namespace OHOS {
namespace WallpaperMgrService {
class WallpaperEventListenerProxy : public IRemoteProxy<IWallpaperEventListener> {
public:
    explicit WallpaperEventListenerProxy(const sptr<IRemoteObject> &object)
        : IRemoteProxy<IWallpaperEventListener>(object)
    {
    }
    ~WallpaperEventListenerProxy() = default;
    static inline BrokerDelegator<WallpaperEventListenerProxy> delegator_;
    void OnColorsChange(const std::vector<uint64_t> &color, int32_t wallpaperType) override;
    void OnWallpaperChange(WallpaperType wallpaperType, WallpaperResourceType resourceType, const std::string &uri) override;
};
} // namespace WallpaperMgrService
} // namespace OHOS

#endif  // WALLPAPER_EVENT_LISTENER_PROXY_H
