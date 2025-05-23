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

#ifndef INNERKITSIMPL_WALLPAPER_MANAGER_COMMON_INFO_H
#define INNERKITSIMPL_WALLPAPER_MANAGER_COMMON_INFO_H

#include <string>

enum WallpaperType {
    /**
     * Indicates the home screen wallpaper.
     */
    WALLPAPER_SYSTEM,
    /**
     * Indicates the lock screen wallpaper.
     */
    WALLPAPER_LOCKSCREEN
};

enum WallpaperResourceType {
    // default wallpaper resource.
    DEFAULT,

    // picture wallpaper resource.
    PICTURE,

    // video wallpaper resource.
    VIDEO,

    // package wallpaper resource.
    PACKAGE
};

enum FoldState {
    NORMAL,
    UNFOLD_1,
    UNFOLD_2
};

enum RotateState {
    PORT,
    LAND
};

struct WallpaperInfo {
    FoldState foldState;
    RotateState rotateState;
    std::string source;
};
#endif