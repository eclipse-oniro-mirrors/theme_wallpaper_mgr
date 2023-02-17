/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

var WindowManager = requireNapi("window")
var WindowName = "wallpaper"
var windowType = 2000
var windowsCreated = false;

class WallpaperExtension {
    createWallpaperWin() {
        console.log(`${WindowName} createWallpaperWin`);

        WindowManager.create(this.context, WindowName, windowType).then((win) => {
            console.log(`${WindowName} wallpaperWindow`);
            this.wallpaperWindow = win;
            console.log(this.wallpaperWindow);
            this.wallpaperWindow.moveTo(0, 0).then(() => {
                this.wallpaperWindow.resetSize(480, 960).then(() => {
                    console.log(`${WindowName} resetSize ${this.wallpaperURI}`);
                    this.loadUiContent(this.wallpaperURI);
                    console.log(`${WindowName} window created`);
                    windowsCreated = true;
                })
            })
        }, (error) => {
            console.log(`${WindowName} window createFailed, error.code = ${error.code}`);
        })
    }

    onCreated(want) {
        console.log(`${WindowName} onWallpaperExtensionCreated`);
    }

    setUiContent(uri) {
        console.log(`${WindowName} setUiContent`);
        if (windowsCreated) {
            console.log(`${WindowName} loadUiContent`);
            loadUiContent(uri);
        } else {
            console.log(`${WindowName} save wallpaperURI`);
            this.wallpaperURI = uri;
        }
    }

    loadUiContent(uri) {
        console.log(`${WindowName} initUiContent ${uri}`);
        this.wallpaperWindow.loadContent(uri).then(() => {
            console.log(`${WindowName} loadContent`);
            this.wallpaperWindow.show().then(() => {
                console.log(`${WindowName} window is show`);
            })
        })
    }

    onWallpaperChanged(wallpaperType) {
        console.log(`${WindowName} onWallpaperChanged ${wallpaperType}`);
    }

    onDestroy() {
        console.log(`${WindowName} onWallpaperExtensionDestroy`);
    }
}

export default WallpaperExtension