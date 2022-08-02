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

#include "js_wallpaper_extension.h"

#include "ability_info.h"
#include "hilog_wrapper.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "js_wallpaper_extension_context.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common_want.h"
#include "napi_remote_object.h"
#include "wallpaper_manager.h"
#include "napi_common_util.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr size_t ARGC_ONE = 1;
}
JsWallpaperExtension* JsWallpaperExtension::jsWallpaperExtension = NULL;
using namespace OHOS::AppExecFwk;
JsWallpaperExtension* JsWallpaperExtension::Create(const std::unique_ptr<Runtime>& runtime)
{
    HILOG_INFO("jws JsWallpaperExtension begin Create");
    jsWallpaperExtension = new JsWallpaperExtension(static_cast<JsRuntime&>(*runtime));
    return jsWallpaperExtension;
}

JsWallpaperExtension::JsWallpaperExtension(JsRuntime& jsRuntime) : jsRuntime_(jsRuntime) {}
JsWallpaperExtension::~JsWallpaperExtension() = default;

void JsWallpaperExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    HILOG_INFO("jws JsWallpaperExtension begin Init");
    WallpaperExtension::Init(record, application, handler, token);
    std::string srcPath = "";
    GetSrcPath(srcPath);
    if (srcPath.empty()) {
        HILOG_ERROR("Failed to get srcPath");
        return;
    }

    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    HILOG_INFO("JsWallpaperExtension::Init module:%{public}s,srcPath:%{public}s.", moduleName.c_str(), srcPath.c_str());
    HandleScope handleScope(jsRuntime_);
    auto& engine = jsRuntime_.GetNativeEngine();

    jsObj_ = jsRuntime_.LoadModule(moduleName, srcPath);
    if (jsObj_ == nullptr) {
        HILOG_ERROR("Failed to get jsObj_");
        return;
    }
    HILOG_INFO("JsWallpaperExtension::Init ConvertNativeValueTo.");
    NativeObject* obj = ConvertNativeValueTo<NativeObject>(jsObj_->Get());
    if (obj == nullptr) {
        HILOG_ERROR("Failed to get JsWallpaperExtension object");
        return;
    }

    auto context = GetContext();
    if (context == nullptr) {
        HILOG_ERROR("Failed to get context");
        return;
    }
    HILOG_INFO("JsWallpaperExtension::Init CreateJsWallpaperExtensionContext.");
    NativeValue* contextObj = CreateJsWallpaperExtensionContext(engine, context);
    auto shellContextRef = jsRuntime_.LoadSystemModule("WallpaperExtensionContext", &contextObj, ARGC_ONE);
    contextObj = shellContextRef->Get();
    HILOG_INFO("JsWallpaperExtension::Init Bind.");
    context->Bind(jsRuntime_, shellContextRef.release());
    HILOG_INFO("JsWallpaperExtension::SetProperty.");
    obj->SetProperty("context", contextObj);

    auto nativeObj = ConvertNativeValueTo<NativeObject>(contextObj);
    if (nativeObj == nullptr) {
        HILOG_ERROR("Failed to get wallpaper extension native object");
        return;
    }

    HILOG_INFO("Set wallpaper extension context pointer: %{public}p", context.get());

    nativeObj->SetNativePointer(new std::weak_ptr<AbilityRuntime::Context>(context),
        [](NativeEngine*, void* data, void*) {
            HILOG_INFO("Finalizer for weak_ptr wallpaper extension context is called");
            delete static_cast<std::weak_ptr<AbilityRuntime::Context>*>(data);
        }, nullptr);

    HILOG_INFO("JsWallpaperExtension::Init end.");
}

void JsWallpaperExtension::OnStart(const AAFwk::Want &want)
{
    Extension::OnStart(want);
    HILOG_INFO("jws JsWallpaperExtension OnStart begin..");
    HandleScope handleScope(jsRuntime_);
    NativeEngine* nativeEngine = &jsRuntime_.GetNativeEngine();
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(reinterpret_cast<napi_env>(nativeEngine), want);
    NativeValue* nativeWant = reinterpret_cast<NativeValue*>(napiWant);
    NativeValue* argv[] = {nativeWant};
    CallObjectMethod("onCreated", argv, ARGC_ONE);
    CallObjectMethod("createWallpaperWin");
    WallpaperMgrService::WallpaperManagerkits::GetInstance().RegisterWallpaperCallback(
        [](int WallpaperType)->bool {
            HILOG_INFO("  jsWallpaperExtension->CallObjectMethod");
            HandleScope handleScope(jsWallpaperExtension->jsRuntime_);
            NativeEngine* nativeEng = &(jsWallpaperExtension->jsRuntime_).GetNativeEngine();
            napi_value type = OHOS::AppExecFwk::WrapInt32ToJS(reinterpret_cast<napi_env>(nativeEng), WallpaperType);
            NativeValue* nativeType = reinterpret_cast<NativeValue*>(type);
            NativeValue* arg[] = {nativeType};
            jsWallpaperExtension->CallObjectMethod("onWallpaperChanged", arg, ARGC_ONE);
            return true;
        });
    HILOG_INFO("%{public}s end.", __func__);
}

void JsWallpaperExtension::OnStop()
{
    WallpaperExtension::OnStop();
    HILOG_INFO("jws JsWallpaperExtension OnStop begin.");
    CallObjectMethod("onDestroy");
    bool ret = ConnectionManager::GetInstance().DisconnectCaller(GetContext()->GetToken());
    if (ret) {
        HILOG_INFO("The wallpaper extension connection is not disconnected.");
    }
    HILOG_INFO("%{public}s end.", __func__);
}

sptr<IRemoteObject> JsWallpaperExtension::OnConnect(const AAFwk::Want &want)
{
    HILOG_INFO("jws JsWallpaperExtension OnConnect begin.");
    Extension::OnConnect(want);
    HILOG_INFO("%{public}s begin.", __func__);
    HandleScope handleScope(jsRuntime_);
    NativeEngine* nativeEngine = &jsRuntime_.GetNativeEngine();
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(reinterpret_cast<napi_env>(nativeEngine), want);
    NativeValue* nativeWant = reinterpret_cast<NativeValue*>(napiWant);
    NativeValue* argv[] = {nativeWant};
    if (!jsObj_) {
        HILOG_WARN("Not found WallpaperExtension.js");
        return nullptr;
    }

    NativeValue* value = jsObj_->Get();
    NativeObject* obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        HILOG_ERROR("Failed to get WallpaperExtension object");
        return nullptr;
    }

    NativeValue* method = obj->GetProperty("onConnect");
    if (method == nullptr) {
        HILOG_ERROR("Failed to get onConnect from WallpaperExtension object");
        return nullptr;
    }
    HILOG_INFO("JsWallpaperExtension::CallFunction onConnect, success");
    NativeValue* remoteNative = nativeEngine->CallFunction(value, method, argv, ARGC_ONE);
    if (remoteNative == nullptr) {
        HILOG_ERROR("remoteNative nullptr.");
    }
    auto remoteObj = NAPI_ohos_rpc_getNativeRemoteObject(
        reinterpret_cast<napi_env>(nativeEngine), reinterpret_cast<napi_value>(remoteNative));
    if (remoteObj == nullptr) {
        HILOG_ERROR("remoteObj nullptr.");
    }
    return remoteObj;
}

void JsWallpaperExtension::OnDisconnect(const AAFwk::Want &want)
{
    HILOG_INFO("jws JsWallpaperExtension OnDisconnect begin.");
    Extension::OnDisconnect(want);
    HILOG_INFO("%{public}s begin.", __func__);
    HandleScope handleScope(jsRuntime_);
    NativeEngine* nativeEngine = &jsRuntime_.GetNativeEngine();
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(reinterpret_cast<napi_env>(nativeEngine), want);
    NativeValue* nativeWant = reinterpret_cast<NativeValue*>(napiWant);
    NativeValue* argv[] = {nativeWant};
    if (!jsObj_) {
        HILOG_WARN("Not found WallpaperExtension.js");
        return;
    }

    NativeValue* value = jsObj_->Get();
    NativeObject* obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        HILOG_ERROR("Failed to get WallpaperExtension object");
        return;
    }

    NativeValue* method = obj->GetProperty("onDisconnect");
    if (method == nullptr) {
        HILOG_ERROR("Failed to get onDisconnect from WallpaperExtension object");
        return;
    }
    nativeEngine->CallFunction(value, method, argv, ARGC_ONE);
    HILOG_INFO("%{public}s end.", __func__);
}

void JsWallpaperExtension::OnCommand(const AAFwk::Want &want, bool restart, int startId)
{
    HILOG_INFO("jws JsWallpaperExtension OnCommand begin.");
    Extension::OnCommand(want, restart, startId);
    HILOG_INFO("%{public}s begin restart=%{public}s,startId=%{public}d.",
        __func__,
        restart ? "true" : "false",
        startId);
    HILOG_INFO("%{public}s end.", __func__);
}

NativeValue* JsWallpaperExtension::CallObjectMethod(const char* name, NativeValue* const* argv, size_t argc)
{
    HILOG_INFO("jws JsWallpaperExtension::CallObjectMethod(%{public}s), begin", name);

    if (!jsObj_) {
        HILOG_WARN("Not found WallpaperExtension.js");
        return nullptr;
    }

    HandleScope handleScope(jsRuntime_);
    auto& nativeEngine = jsRuntime_.GetNativeEngine();

    NativeValue* value = jsObj_->Get();
    NativeObject* obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        HILOG_ERROR("Failed to get WallpaperExtension object");
        return nullptr;
    }

    NativeValue* method = obj->GetProperty(name);
    if (method == nullptr) {
        HILOG_ERROR("Failed to get '%{public}s' from WallpaperExtension object", name);
        return nullptr;
    }
    HILOG_INFO("JsWallpaperExtension::CallFunction(%{public}s), success", name);
    return nativeEngine.CallFunction(value, method, argv, argc);
}

void JsWallpaperExtension::GetSrcPath(std::string &srcPath)
{
    HILOG_INFO("jws JsWallpaperExtension GetSrcPath begin.");
    if (!Extension::abilityInfo_->isModuleJson) {
        /* temporary compatibility api8 + config.json */
        srcPath.append(Extension::abilityInfo_->package);
        srcPath.append("/assets/js/");
        if (!Extension::abilityInfo_->srcPath.empty()) {
            srcPath.append(Extension::abilityInfo_->srcPath);
        }
        srcPath.append("/").append(Extension::abilityInfo_->name).append(".abc");
        return;
    }

    if (!Extension::abilityInfo_->srcEntrance.empty()) {
        srcPath.append(Extension::abilityInfo_->moduleName + "/");
        srcPath.append(Extension::abilityInfo_->srcEntrance);
        srcPath.erase(srcPath.rfind('.'));
        srcPath.append(".abc");
    }
}
}
}
