/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#define private public
#define protected public
#include "wallpaper_service.h"
#undef private
#undef protected

#include <gtest/gtest.h>

#include <ctime>

#include "accesstoken_kit.h"
#include "directory_ex.h"
#include "file_deal.h"
#include "hilog_wrapper.h"
#include "image_packer.h"
#include "nativetoken_kit.h"
#include "pixel_map.h"
#include "scene_board_judgement.h"
#include "token_setproc.h"
#include "wallpaper_common_event_subscriber.h"
#include "wallpaper_manager.h"
#include "wallpaper_manager_client.h"
#include "wallpaper_service.h"

namespace OHOS {
namespace WallpaperMgrService {
constexpr int32_t SYSTYEM = 0;
constexpr int32_t LOCKSCREEN = 1;
constexpr int32_t INVALID_WALLPAPER_TYPE = 2;
constexpr int32_t HUNDRED = 100;
constexpr int32_t DEFAULT_WALLPAPER_ID = -1;
constexpr int32_t FOO_MAX_LEN = 60000000;
constexpr int32_t TEST_USERID = 99;
constexpr int32_t TEST_USERID1 = 98;
constexpr int32_t INVALID_USERID = -1;
constexpr int32_t NORMAL = 0;
constexpr int32_t UNFOLD_1 = 1;
constexpr int32_t UNFOLD_2 = 2;
constexpr int32_t PORT = 0;
constexpr int32_t LAND = 1;
constexpr int32_t DEFAULT_USERID = 100;
uint64_t selfTokenID_ = 0;
constexpr const char *URI = "/data/test/theme/wallpaper/wallpaper_test.JPG";
constexpr const char *NORMAL_PORT_URI = "/data/test/theme/wallpaper/normal_port_wallpaper.jpg";
constexpr const char *NORMAL_LAND_URI = "/data/test/theme/wallpaper/normal_land_wallpaper.jpg";
constexpr const char *UNFOLD1_PORT_URI = "/data/test/theme/wallpaper/unfold1_port_wallpaper.jpg";
constexpr const char *UNFOLD1_LAND_URI = "/data/test/theme/wallpaper/unfold1_land_wallpaper.jpg";
constexpr const char *UNFOLD2_PORT_URI = "/data/test/theme/wallpaper/unfold2_port_wallpaper.jpg";
constexpr const char *UNFOLD2_LAND_URI = "/data/test/theme/wallpaper/unfold2_land_wallpaper.jpg";
constexpr const char *URI_ZIP = "/data/test/theme/wallpaper/test.zip";
constexpr const char *URI_30FPS_3S_MP4 = "/data/test/theme/wallpaper/30fps_3s.mp4";
constexpr const char *URI_15FPS_7S_MP4 = "/data/test/theme/wallpaper/15fps_7s.mp4";
constexpr const char *URI_30FPS_3S_MOV = "/data/test/theme/wallpaper/30fps_3s.mov";
constexpr const char *WALLPAPER_DEFAULT_PATH = "/data/service/el1/public/wallpaper";
constexpr const char *SYSTEM_DIR = "/system";
constexpr const char *LOCKSCREEN_DIR = "/lockscreen";
constexpr const char *LOCKSCREEN_FILE = "/lockscreen/wallpaper_lock";
constexpr const char *WALLPAPER_DEFAULT = "wallpaperdefault.jpeg";
constexpr const char *HOME_WALLPAPER = "home_wallpaper_0.jpg";

std::shared_ptr<WallpaperCommonEventSubscriber> subscriber = nullptr;

using namespace testing::ext;
using namespace testing;
using namespace OHOS::Media;
using namespace OHOS::HiviewDFX;
using namespace OHOS::MiscServices;
using namespace OHOS::Security::AccessToken;

static HapPolicyParams policyParams = { .apl = APL_SYSTEM_CORE,
    .domain = "test.domain",
    .permList = { { .permissionName = "ohos.permission.GET_WALLPAPER",
                      .bundleName = "ohos.wallpaper_test.demo",
                      .grantMode = 1,
                      .availableLevel = APL_NORMAL,
                      .label = "label",
                      .labelId = 1,
                      .description = "test",
                      .descriptionId = 1 },
        { .permissionName = "ohos.permission.SET_WALLPAPER",
            .bundleName = "ohos.wallpaper_test.demo",
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = "label",
            .labelId = 1,
            .description = "test",
            .descriptionId = 1 },
        { .permissionName = "ohos.permission.MANAGE_LOCAL_ACCOUNTS",
            .bundleName = "ohos.wallpaper_test.demo",
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = "label",
            .labelId = 1,
            .description = "test",
            .descriptionId = 1 } },
    .permStateList = { { .permissionName = "ohos.permission.GET_WALLPAPER",
                           .isGeneral = true,
                           .resDeviceID = { "local" },
                           .grantStatus = { PermissionState::PERMISSION_GRANTED },
                           .grantFlags = { 1 } },
        { .permissionName = "ohos.permission.SET_WALLPAPER",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 } },
        { .permissionName = "ohos.permission.MANAGE_LOCAL_ACCOUNTS",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 } } } };

HapInfoParams infoParams = { .userID = 1,
    .bundleName = "wallpaper_service",
    .instIndex = 0,
    .appIDDesc = "test",
    .apiVersion = 9,
    .isSystemApp = true };

static WallpaperInfo wallpaperInfo_normal_port = { FoldState::NORMAL, RotateState::PORT, NORMAL_PORT_URI };
static WallpaperInfo wallpaperInfo_normal_land = { FoldState::NORMAL, RotateState::LAND, NORMAL_LAND_URI };
static WallpaperInfo wallpaperInfo_unfold1_port = { FoldState::UNFOLD_1, RotateState::PORT, UNFOLD1_PORT_URI };
static WallpaperInfo wallpaperInfo_unfold1_land = { FoldState::UNFOLD_1, RotateState::LAND, UNFOLD1_LAND_URI };
static WallpaperInfo wallpaperInfo_unfold2_port = { FoldState::UNFOLD_2, RotateState::PORT, UNFOLD2_PORT_URI };
static WallpaperInfo wallpaperInfo_unfold2_land = { FoldState::UNFOLD_2, RotateState::LAND, UNFOLD2_LAND_URI };

void GrantNativePermission()
{
    selfTokenID_ = GetSelfTokenID();
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(infoParams, policyParams);
    int32_t ret = SetSelfTokenID(tokenIdEx.tokenIDEx);
    if (ret == 0) {
        HILOG_INFO("SetSelfTokenID success!");
    } else {
        HILOG_ERROR("SetSelfTokenID fail!");
    }
}

class WallpaperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void CreateTempImage();
    static std::shared_ptr<PixelMap> CreateTempPixelMap();
    static bool SubscribeCommonEvent(shared_ptr<WallpaperService> wallpaperService);
    static void TriggerEvent(int32_t userId, const std::string &commonEventSupport);
    static std::string GetUserFilePath(int32_t userId, const char *filePath);
    static bool TestCallBack(int32_t num);
};
const std::string VALID_SCHEMA_STRICT_DEFINE = "{\"SCHEMA_VERSION\":\"1.0\","
                                               "\"SCHEMA_MODE\":\"STRICT\","
                                               "\"SCHEMA_SKIPSIZE\":0,"
                                               "\"SCHEMA_DEFINE\":{"
                                               "\"age\":\"INTEGER, NOT NULL\""
                                               "},"
                                               "\"SCHEMA_INDEXES\":[\"$.age\"]}";

void WallpaperTest::SetUpTestCase(void)
{
    HILOG_INFO("SetUpTestCase");
    GrantNativePermission();
    CreateTempImage();
    HILOG_INFO("SetUpTestCase end");
}

void WallpaperTest::TearDownTestCase(void)
{
    HILOG_INFO("TearDownTestCase");
    ApiInfo apiInfo{ false, false };
    WallpaperManager::GetInstance().ResetWallpaper(SYSTYEM, apiInfo);
    WallpaperManager::GetInstance().ResetWallpaper(LOCKSCREEN, apiInfo);
    auto ret = SetSelfTokenID(selfTokenID_);
    HILOG_INFO("SetSelfTokenID ret = %{public}d", ret);
}

void WallpaperTest::SetUp(void)
{
}

void WallpaperTest::TearDown(void)
{
}

class WallpaperEventListenerTestImpl : public WallpaperEventListener {
public:
    std::vector<uint64_t> color_;
    int32_t wallpaperType_;
    WallpaperEventListenerTestImpl();
    ~WallpaperEventListenerTestImpl()
    {
    }

    WallpaperEventListenerTestImpl(const WallpaperEventListenerTestImpl &) = delete;
    WallpaperEventListenerTestImpl &operator=(const WallpaperEventListenerTestImpl &) = delete;
    WallpaperEventListenerTestImpl(WallpaperEventListenerTestImpl &&) = delete;
    WallpaperEventListenerTestImpl &operator=(WallpaperEventListenerTestImpl &&) = delete;

    // callback function will be called when the db data is changed.
    void OnColorsChange(const std::vector<uint64_t> &color, int32_t wallpaperType) override;
    void OnWallpaperChange(
        WallpaperType wallpaperType, WallpaperResourceType resourceType, const std::string &uri) override;
    // reset the callCount_ to zero.
    void ResetToZero();

    unsigned long GetCallCount() const;

private:
    unsigned long callCount_;
};

void WallpaperEventListenerTestImpl::OnColorsChange(const std::vector<uint64_t> &color, int32_t wallpaperType)
{
    callCount_++;
    for (auto const &each : color) {
        color_.push_back(each);
    }
    wallpaperType_ = wallpaperType;
}

void WallpaperEventListenerTestImpl::OnWallpaperChange(
    WallpaperType wallpaperType, WallpaperResourceType resourceType, const std::string &uri)
{
    HILOG_INFO("wallpaperType: %{public}d, resourceType: %{public}d, uri: %{public}s",
        static_cast<int32_t>(wallpaperType), static_cast<int32_t>(resourceType), uri.c_str());
}

WallpaperEventListenerTestImpl::WallpaperEventListenerTestImpl()
{
    callCount_ = 0;
    wallpaperType_ = -1;
}

void WallpaperEventListenerTestImpl::ResetToZero()
{
    callCount_ = 0;
}

unsigned long WallpaperEventListenerTestImpl::GetCallCount() const
{
    return callCount_;
}

void WallpaperTest::CreateTempImage()
{
    std::shared_ptr<PixelMap> pixelMap = CreateTempPixelMap();
    ImagePacker imagePacker;
    PackOption option;
    option.format = "image/jpeg";
    option.quality = HUNDRED;
    option.numberHint = 1;
    std::set<std::string> formats;
    imagePacker.GetSupportedFormats(formats);
    imagePacker.StartPacking(URI, option);
    HILOG_INFO("AddImage start");
    imagePacker.AddImage(*pixelMap);
    int64_t packedSize = 0;
    HILOG_INFO("FinalizePacking start");
    imagePacker.FinalizePacking(packedSize);
    if (packedSize == 0) {
        HILOG_INFO("FinalizePacking error");
    }
}

std::shared_ptr<PixelMap> WallpaperTest::CreateTempPixelMap()
{
    uint32_t color[100] = { 3, 7, 9, 9, 7, 6 };
    InitializationOptions opts = { { 5, 7 }, OHOS::Media::PixelFormat::ARGB_8888 };
    std::unique_ptr<PixelMap> uniquePixelMap = PixelMap::Create(color, sizeof(color) / sizeof(color[0]), opts);
    std::shared_ptr<PixelMap> pixelMap = std::move(uniquePixelMap);
    return pixelMap;
}

bool WallpaperTest::SubscribeCommonEvent(shared_ptr<WallpaperService> wallpaperService)
{
    subscriber = std::make_shared<WallpaperCommonEventSubscriber>(*wallpaperService);
    if (subscriber == nullptr) {
        HILOG_INFO("wallpaperCommonEvent is nullptr");
        return false;
    }
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber)) {
        HILOG_INFO("SubscribeCommonEvent  failed");
        return false;
    }
    return true;
}

void WallpaperTest::TriggerEvent(int32_t userId, const std::string &commonEventSupport)
{
    EventFwk::Want want;
    want.SetAction(commonEventSupport);
    int32_t code = userId;
    std::string data(commonEventSupport);
    EventFwk::CommonEventData eventData(want, code, data);
    subscriber->OnReceiveEvent(eventData);
}

std::string WallpaperTest::GetUserFilePath(int32_t userId, const char *filePath)
{
    return WALLPAPER_DEFAULT_PATH + std::string("/") + std::to_string(userId) + filePath;
}

bool WallpaperTest::TestCallBack(int32_t num)
{
    if (num > 0) {
        return true;
    }
    return false;
}
/*********************   ResetWallpaper   *********************/
/**
* @tc.name:    Reset001
* @tc.desc:    Reset wallpaper with wallpaperType[0].
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, Reset001, TestSize.Level1)
{
    HILOG_INFO("Reset001 begin.");
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().ResetWallpaper(SYSTYEM, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to reset.";
}

/**
* @tc.name:    Reset002
* @tc.desc:    Reset wallpaper with wallpaperType[1].
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, Reset002, TestSize.Level1)
{
    HILOG_INFO("Reset002 begin.");
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().ResetWallpaper(LOCKSCREEN, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to reset.";
}

/**
* @tc.name:    Reset003
* @tc.desc:    Reset wallpaper with wallpaperType[2] throw parameters error.
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, Reset003, TestSize.Level1)
{
    HILOG_INFO("Reset003 begin.");
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().ResetWallpaper(INVALID_WALLPAPER_TYPE, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_PARAMETERS_INVALID) << "Failed to throw error.";
}

/**
* @tc.name:    Reset004
* @tc.desc:    Reset wallpaper with wallpaperType[0] after resetting wallpaper[0].
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, Reset004, TestSize.Level1)
{
    HILOG_INFO("Reset004 begin.");
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().ResetWallpaper(SYSTYEM, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to reset.";

    /* duplicate reset */
    wallpaperErrorCode = WallpaperManager::GetInstance().ResetWallpaper(SYSTYEM, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to reset.";
}

/**
* @tc.name:    Reset005
* @tc.desc:    Reset wallpaper with wallpaperType[1] after resetting wallpaper[1] and check whether Id is same one.
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, Reset005, TestSize.Level1)
{
    HILOG_INFO("Reset005 begin.");
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().ResetWallpaper(LOCKSCREEN, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to reset.";
    int32_t firstId = WallpaperManager::GetInstance().GetWallpaperId(LOCKSCREEN);

    /* duplicate reset */
    wallpaperErrorCode = WallpaperManager::GetInstance().ResetWallpaper(LOCKSCREEN, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to reset.";
    int32_t secondId = WallpaperManager::GetInstance().GetWallpaperId(LOCKSCREEN);
    EXPECT_EQ(firstId, secondId) << "Id should be same one.";
}

/**
* @tc.name:    Reset006
* @tc.desc:    Reset wallpaper throw permission error
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, Reset006, TestSize.Level1)
{
    HILOG_INFO("Reset006 begin.");
    ApiInfo apiInfo{ true, true };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().ResetWallpaper(LOCKSCREEN, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK);
    wallpaperErrorCode = WallpaperManager::GetInstance().ResetWallpaper(SYSTYEM, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK);
}
/*********************   ResetWallpaper   *********************/

/*********************   IsChangePermitted   *********************/

/**
* @tc.name: IsChangePermitted001
* @tc.desc: check permission.
* @tc.type: FUNC
* @tc.require:
* @tc.author:
*/
HWTEST_F(WallpaperTest, IsChangePermitted001, TestSize.Level1)
{
    EXPECT_EQ(WallpaperManager::GetInstance().IsChangePermitted(), true);
}

/*********************   IsChangePermitted   *********************/

/*********************   IsOperationAllowed   *********************/

/**
* @tc.name: IsOperationAllowed001
* @tc.desc: check permission.
* @tc.type: FUNC
* @tc.require:
* @tc.author:
*/
HWTEST_F(WallpaperTest, IsOperationAllowed001, TestSize.Level1)
{
    EXPECT_EQ(WallpaperManager::GetInstance().IsOperationAllowed(), true);
}

/*********************   IsOperationAllowed   *********************/

/*********************   On & Off   *********************/

/**
* @tc.name: On001
* @tc.desc: set wallpaper and get callback.
* @tc.type: FUNC
* @tc.require:
* @tc.author:
*/
HWTEST_F(WallpaperTest, On001, TestSize.Level1)
{
    HILOG_INFO("On001 begin");
    auto listener = std::make_shared<WallpaperEventListenerTestImpl>();
    auto status = WallpaperManager::GetInstance().On("colorChange", listener);
    EXPECT_EQ(status, E_OK) << "subscribe wallpaper color change failed.";
    auto offSubStatus = WallpaperManager::GetInstance().Off("colorChange", listener);
    EXPECT_EQ(offSubStatus, E_OK) << "unsubscribe wallpaper color change failed.";
}

/**
* @tc.name: On002
* @tc.desc: set wallpaper and get callback.
* @tc.type: FUNC
* @tc.require:
* @tc.author:
*/
HWTEST_F(WallpaperTest, On002, TestSize.Level1)
{
    HILOG_INFO("On002 begin");
    auto listener = std::make_shared<WallpaperEventListenerTestImpl>();
    auto status = WallpaperManager::GetInstance().On("wallpaperChange", listener);
    EXPECT_EQ(status, E_OK);
    auto offSubStatus = WallpaperManager::GetInstance().Off("wallpaperChange", listener);
    EXPECT_EQ(offSubStatus, E_OK);
}

/*********************   On & Off   *********************/

/*********************   GetColors   *********************/
/**
* @tc.name: GetColors001
* @tc.desc: GetColors with wallpaperType[0].
* @tc.type: FUNC
* @tc.require:
* @tc.author:
*/
HWTEST_F(WallpaperTest, GetColors001, TestSize.Level0)
{
    HILOG_INFO("GetColors001 begin");
    std::vector<uint64_t> colors;
    ApiInfo apiInfo{ false, false };
    ErrorCode errorCode = WallpaperManager::GetInstance().GetColors(SYSTYEM, apiInfo, colors);
    EXPECT_EQ(errorCode, E_OK) << "Failed to GetColors.";
    EXPECT_FALSE(colors.empty());
}

/**
* @tc.name: GetColors002
* @tc.desc: GetColors with wallpaperType[1].
* @tc.type: FUNC
* @tc.require:
* @tc.author:
*/
HWTEST_F(WallpaperTest, GetColors002, TestSize.Level0)
{
    HILOG_INFO("GetColors002 begin");
    std::vector<uint64_t> colors;
    ApiInfo apiInfo{ false, false };
    ErrorCode errorCode = WallpaperManager::GetInstance().GetColors(LOCKSCREEN, apiInfo, colors);
    EXPECT_EQ(errorCode, E_OK) << "Failed to GetColors.";
    EXPECT_FALSE(colors.empty());
}

/**
* @tc.name: GetColors003
* @tc.desc: GetColors throw permission error.
* @tc.type: FUNC
* @tc.require:
* @tc.author:
*/
HWTEST_F(WallpaperTest, GetColors003, TestSize.Level0)
{
    HILOG_INFO("GetColors003 begin");
    std::vector<uint64_t> colors;
    ApiInfo apiInfo{ true, true };
    ErrorCode errorCode = WallpaperManager::GetInstance().GetColors(LOCKSCREEN, apiInfo, colors);
    EXPECT_EQ(errorCode, E_OK);
    errorCode = WallpaperManager::GetInstance().GetColors(SYSTYEM, apiInfo, colors);
    EXPECT_EQ(errorCode, E_OK);
}
/*********************   GetColors   *********************/

/*********************   GetId   *********************/
/**
* @tc.name: GetId001
* @tc.desc: GetId with wallpaperType[0].
* @tc.type: FUNC
* @tc.require: issueI65VF1
* @tc.author: lvbai
*/
HWTEST_F(WallpaperTest, GetId001, TestSize.Level0)
{
    HILOG_INFO("GetId001 begin");
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().ResetWallpaper(SYSTYEM, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to ResetWallpaper";
    int32_t id = WallpaperManager::GetInstance().GetWallpaperId(SYSTYEM);
    EXPECT_EQ(id, DEFAULT_WALLPAPER_ID) << "Failed to GetId";
}

/**
* @tc.name: GetId002
* @tc.desc: GetId with wallpaperType[1].
* @tc.type: FUNC
* @tc.require: issueI65VF1
* @tc.author: lvbai
*/
HWTEST_F(WallpaperTest, GetId002, TestSize.Level0)
{
    HILOG_INFO("GetId002 begin");
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().ResetWallpaper(LOCKSCREEN, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to ResetWallpaper";
    int32_t id = WallpaperManager::GetInstance().GetWallpaperId(LOCKSCREEN);
    EXPECT_EQ(id, DEFAULT_WALLPAPER_ID) << "Failed to GetId";
}

/**
* @tc.name: GetId003
* @tc.desc: GetId with wallpaperType[0] after setWallpaper.
* @tc.type: FUNC
* @tc.require: issueI65VF1
* @tc.author: lvbai
*/
HWTEST_F(WallpaperTest, GetId003, TestSize.Level0)
{
    HILOG_INFO("GetId003 begin");
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().SetWallpaper(URI, SYSTYEM, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to SetWallpaper";
    int32_t id = WallpaperManager::GetInstance().GetWallpaperId(SYSTYEM);
    EXPECT_GT(id, DEFAULT_WALLPAPER_ID) << "Failed to GetId";
}

/**
* @tc.name: GetId004
* @tc.desc: GetId with wallpaperType[1] after setWallpaper.
* @tc.type: FUNC
* @tc.require: issueI65VF1
* @tc.author: lvbai
*/
HWTEST_F(WallpaperTest, GetId004, TestSize.Level0)
{
    HILOG_INFO("GetId004 begin");
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().SetWallpaper(URI, LOCKSCREEN, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to SetWallpaper";
    int32_t id = WallpaperManager::GetInstance().GetWallpaperId(LOCKSCREEN);
    EXPECT_GT(id, DEFAULT_WALLPAPER_ID) << "Failed to GetId";
}
/*********************   GetId   *********************/

/*********************   GetFile   *********************/
/**
* @tc.name:    GetFile001
* @tc.desc:    GetFile with wallpaperType[0].
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, GetFile001, TestSize.Level0)
{
    HILOG_INFO("GetFile001 begin");
    int32_t wallpaperFd = 0;
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().GetFile(SYSTYEM, wallpaperFd);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to get File.";
}

/**
* @tc.name:    GetFile002
* @tc.desc:    GetFile with wallpaperType[1].
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, GetFile002, TestSize.Level0)
{
    HILOG_INFO("GetFile002 begin");
    int32_t wallpaperFd = 0;
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().GetFile(LOCKSCREEN, wallpaperFd);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to get File.";
}

/**
* @tc.name:    GetFile003
* @tc.desc:    GetFile with wallpaperType[2] throw parameters error.
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, GetFile003, TestSize.Level0)
{
    HILOG_INFO("GetFile003 begin");
    int32_t wallpaperFd = 0;
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().GetFile(INVALID_WALLPAPER_TYPE, wallpaperFd);
    EXPECT_EQ(wallpaperErrorCode, E_PARAMETERS_INVALID) << "Failed to throw parameters error";
}

/**
* @tc.name:    GetFile004
* @tc.desc:    GetFile with wallpaperType[0].
* @tc.type:    FUNC
* @tc.require:
* @tc.author:
*/
HWTEST_F(WallpaperTest, GetFile004, TestSize.Level0)
{
    HILOG_INFO("GetFile001 begin");
    int32_t wallpaperFd = 0;
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().GetFile(SYSTYEM, wallpaperFd);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to get File.";
}
/*********************   GetFile   *********************/

/*********************   GetWallpaperMinHeight   *********************/
/**
* @tc.name: getMinHeight001
* @tc.desc: GetWallpaperMinHeight .
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, getMinHeight001, TestSize.Level0)
{
    HILOG_INFO("getMinHeight001  begin");
    int32_t height = 0;
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().GetWallpaperMinHeight(apiInfo, height);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to get WallpaperMinHeight.";
    EXPECT_GT(height, 0);
}

/**
* @tc.name: getMinHeight002
* @tc.desc: GetWallpaperMinHeight throw permission error.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, getMinHeight002, TestSize.Level0)
{
    HILOG_INFO("getMinHeight002  begin");
    int32_t height = 0;
    ApiInfo apiInfo{ true, true };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().GetWallpaperMinHeight(apiInfo, height);
    EXPECT_EQ(wallpaperErrorCode, E_OK);
}
/*********************   GetWallpaperMinHeight   *********************/

/*********************   GetWallpaperMinWidth   *********************/
/**
* @tc.name: getMinWidth001
* @tc.desc: GetWallpaperMinWidth .
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, getMinWidth001, TestSize.Level0)
{
    HILOG_INFO("getMinWidth001  begin");
    int32_t width = 0;
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().GetWallpaperMinWidth(apiInfo, width);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to get WallpaperMinWidth.";
    EXPECT_GT(width, 0);
}

/**
* @tc.name: getMinWidth002
* @tc.desc: GetWallpaperMinWidth throw permission error.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, getMinWidth002, TestSize.Level0)
{
    HILOG_INFO("getMinWidth002  begin");
    int32_t width = 0;
    ApiInfo apiInfo{ true, true };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().GetWallpaperMinWidth(apiInfo, width);
    EXPECT_EQ(wallpaperErrorCode, E_OK);
}
/*********************   GetWallpaperMinWidth   *********************/

/*********************   GetPixelMap   *********************/
/**
* @tc.name:    GetPixelMap001
* @tc.desc:    GetPixelMap with wallpaperType[0].
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, GetPixelMap001, TestSize.Level0)
{
    HILOG_INFO("GetPixelMap001  begin");
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap;
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().GetPixelMap(SYSTYEM, apiInfo, pixelMap);
    EXPECT_EQ(wallpaperErrorCode, E_OK);
}

/**
* @tc.name:    GetPixelMap002
* @tc.desc:    GetPixelMap with wallpaperType[1].
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, GetPixelMap002, TestSize.Level0)
{
    HILOG_INFO("GetPixelMap002  begin");
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap;
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().GetPixelMap(LOCKSCREEN, apiInfo, pixelMap);
    EXPECT_EQ(wallpaperErrorCode, E_OK);
}

/**
* @tc.name:    GetPixelMap003
* @tc.desc:    GetPixelMap throw permission error.
* @tc.type:    FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, GetPixelMap003, TestSize.Level0)
{
    HILOG_INFO("GetPixelMap003  begin");
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap;
    ApiInfo apiInfo{ true, true };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().GetPixelMap(LOCKSCREEN, apiInfo, pixelMap);
    EXPECT_EQ(wallpaperErrorCode, E_OK);
    wallpaperErrorCode = WallpaperManager::GetInstance().GetPixelMap(SYSTYEM, apiInfo, pixelMap);
    EXPECT_EQ(wallpaperErrorCode, E_OK);
}
/*********************   GetPixelMap   *********************/

/*********************   SetWallpaperByMap   *********************/
/**
* @tc.name:    SetWallpaperByMap001
* @tc.desc:    SetWallpaperByMap with wallpaperType[0].
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, SetWallpaperByMap001, TestSize.Level0)
{
    HILOG_INFO("SetWallpaperByMap001  begin");
    std::shared_ptr<PixelMap> pixelMap = WallpaperTest::CreateTempPixelMap();
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().SetWallpaper(pixelMap, SYSTYEM, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to set SYSTYEM PixelMap.";
    apiInfo.isSystemApi = true;
    wallpaperErrorCode = WallpaperManager::GetInstance().SetWallpaper(pixelMap, SYSTYEM, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to set SYSTYEM PixelMap.";
}

/**
* @tc.name:    SetWallpaperByMap002
* @tc.desc:    SetWallpaperByMap with wallpaperType[1].
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, SetWallpaperByMap002, TestSize.Level0)
{
    HILOG_INFO("SetWallpaperByMap002  begin");
    std::shared_ptr<PixelMap> pixelMap = WallpaperTest::CreateTempPixelMap();
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().SetWallpaper(pixelMap, LOCKSCREEN, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to set LOCKSCREEN PixelMap.";
    apiInfo.isSystemApi = true;
    wallpaperErrorCode = WallpaperManager::GetInstance().SetWallpaper(pixelMap, LOCKSCREEN, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to set LOCKSCREEN PixelMap.";
}

/**
* @tc.name:    SetWallpaperByMap003
* @tc.desc:    SetWallpaperByMap with wallpaperType[2] throw parameters error.
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, SetWallpaperByMap003, TestSize.Level0)
{
    HILOG_INFO("SetWallpaperByMap003  begin");
    std::shared_ptr<PixelMap> pixelMap = WallpaperTest::CreateTempPixelMap();
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode =
        WallpaperManager::GetInstance().SetWallpaper(pixelMap, INVALID_WALLPAPER_TYPE, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_PARAMETERS_INVALID) << "Failed to throw parameters error";
}
/*********************   SetWallpaperByMap   *********************/

/*********************   SetWallpaperByUri   *********************/
/**
* @tc.name:    SetWallpaperByUri001
* @tc.desc:    SetWallpaperByUri with wallpaperType[0] .
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, SetWallpaperByUri001, TestSize.Level0)
{
    HILOG_INFO("SetWallpaperByUri001  begin");
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().SetWallpaper(URI, SYSTYEM, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to set SYSTYEM.";
}

/**
* @tc.name:    SetWallpaperByUri002
* @tc.desc:    SetWallpaperByUri with wallpaperType[1].
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, SetWallpaperByUri002, TestSize.Level0)
{
    HILOG_INFO("SetWallpaperByUri002  begin");
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().SetWallpaper(URI, LOCKSCREEN, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to set LOCKSCREEN.";
}

/**
* @tc.name:    SetWallpaperByUri003
* @tc.desc:    SetWallpaperByUri with wallpaperType[2] throw parameters error.
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, SetWallpaperByUri003, TestSize.Level0)
{
    HILOG_INFO("SetWallpaperByUri003  begin");
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().SetWallpaper(URI, INVALID_WALLPAPER_TYPE, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_PARAMETERS_INVALID) << "Failed to throw error";
}

/**
* @tc.name:    SetWallpaperByUri004
* @tc.desc:    SetWallpaperByUri with error uri.
* @tc.type:    FUNC
* @tc.require: issueI5UHRG
*/
HWTEST_F(WallpaperTest, SetWallpaperByUri004, TestSize.Level0)
{
    HILOG_INFO("SetWallpaperByUri004  begin");
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode =
        WallpaperManager::GetInstance().SetWallpaper("/data/test/theme/wallpaper/errorURI", LOCKSCREEN, apiInfo);
    EXPECT_NE(wallpaperErrorCode, E_OK) << "Failed to throw error";
}

/**
* @tc.name:    SetWallpaperByUri005
* @tc.desc:    SetWallpaperByUri with unsafe uri.
* @tc.type:    FUNC
* @tc.require: issueI647HI
*/
HWTEST_F(WallpaperTest, SetWallpaperByUri005, TestSize.Level0)
{
    HILOG_INFO("SetWallpaperByUri005  begin");
    ApiInfo apiInfo{ false, false };
    ErrorCode wallpaperErrorCode =
        WallpaperManager::GetInstance().SetWallpaper("../data/test/theme/wallpaper/errorURI", LOCKSCREEN, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_PARAMETERS_INVALID) << "Failed to return error";
}

/**
* @tc.name:    SetWallpaperByUri006
* @tc.desc:    SetWallpaperByUri throw permission error.
* @tc.type:    FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, SetWallpaperByUri006, TestSize.Level0)
{
    HILOG_INFO("SetWallpaperByUri006  begin");
    ApiInfo apiInfo{ true, true };
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().SetWallpaper(URI, LOCKSCREEN, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK);
    wallpaperErrorCode = WallpaperManager::GetInstance().SetWallpaper(URI, SYSTYEM, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK);
}

/**
* @tc.name:    SetWallpaperByUri007
* @tc.desc:    SetWallpaperByUri throw permission error.
* @tc.type:    FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, SetWallpaperByUri007, TestSize.Level0)
{
    HILOG_INFO("SetWallpaperByUri007  begin");
    ApiInfo apiInfo{ true, true };
    WallpaperManager::GetInstance().ResetWallpaper(LOCKSCREEN, apiInfo);
    std::shared_ptr<WallpaperService> wallpaperService = std::make_shared<WallpaperService>();
    int32_t userId = wallpaperService->QueryActiveUserId();
    HILOG_INFO("guochao  userId:%{public}d", userId);
    bool ret = FileDeal::IsFileExist(WallpaperTest::GetUserFilePath(userId, LOCKSCREEN_FILE));
    EXPECT_EQ(ret, false) << "Failed to reset.";
    WallpaperManager::GetInstance().SetWallpaper(URI, LOCKSCREEN, apiInfo);
    ret = FileDeal::IsFileExist(WallpaperTest::GetUserFilePath(userId, LOCKSCREEN_FILE));
    EXPECT_EQ(ret, true);
    WallpaperManager::GetInstance().ResetWallpaper(LOCKSCREEN, apiInfo);
}

/*********************   SetWallpaperByUri   *********************/

/*********************   FILE_DEAL   *********************/
/**
* @tc.name:    FILE_DEAL001
* @tc.desc:    File operation-related interfaces
* @tc.type:    FUNC
* @tc.require:
* @tc.author:
*/
HWTEST_F(WallpaperTest, FILE_DEAL001, TestSize.Level0)
{
    HILOG_INFO("FILE_DEAL001  begin");
    FileDeal fileOperation;
    bool isExist = fileOperation.Mkdir("/data/test/theme/wallpaper/");
    EXPECT_EQ(isExist, true);
    isExist = fileOperation.Mkdir("/data/test/theme/errorURI/");
    EXPECT_EQ(isExist, true);
    isExist = fileOperation.IsFileExist(URI);
    EXPECT_EQ(isExist, true);
    isExist = fileOperation.IsFileExist("/data/test/theme/wallpaper/errorURI");
    EXPECT_EQ(isExist, false);
}
/*********************   FILE_DEAL   *********************/

/**
* @tc.name:    SetWallpaper001
* @tc.desc:    SetWallpaper with error length
* @tc.type:    FUNC
* @tc.require: issueI6AW6M
* @tc.author:  weishaoxiong
*/
HWTEST_F(WallpaperTest, SetWallpaper001, TestSize.Level0)
{
    HILOG_INFO("SetWallpaper001  begin");
    std::shared_ptr<WallpaperService> wallpaperService = std::make_shared<WallpaperService>();
    ErrCode wallpaperErrorCode = wallpaperService->SetWallpaper(0, 0, -1);
    EXPECT_EQ(wallpaperErrorCode, E_PARAMETERS_INVALID) << "Failed to throw error";
    wallpaperErrorCode = wallpaperService->SetWallpaper(0, 0, FOO_MAX_LEN);

    EXPECT_EQ(wallpaperErrorCode, E_PICTURE_OVERSIZED) << "Failed to throw error";
}

/*********************   USER_DEAL   *********************/
/**
* @tc.name:    AddUsersDeal001
* @tc.desc:    Create a user directory after the user is added
* @tc.type:    FUNC
* @tc.require: issueI6DWHR
*/
HWTEST_F(WallpaperTest, AddUsersDeal001, TestSize.Level0)
{
    std::shared_ptr<WallpaperService> wallpaperService = std::make_shared<WallpaperService>();
    bool ret = WallpaperTest::SubscribeCommonEvent(wallpaperService);
    ASSERT_EQ(ret, true);
    std::string commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_USER_ADDED;
    WallpaperTest::TriggerEvent(TEST_USERID, commonEvent);
    ret = FileDeal::IsDirExist(WallpaperTest::GetUserFilePath(TEST_USERID, SYSTEM_DIR));
    EXPECT_EQ(ret, true);
    ret = FileDeal::IsDirExist(WallpaperTest::GetUserFilePath(TEST_USERID, LOCKSCREEN_DIR));
    EXPECT_EQ(ret, true);
    std::string userDir = WALLPAPER_DEFAULT_PATH + std::string("/") + std::to_string(TEST_USERID);
    if (!OHOS::ForceRemoveDirectory(userDir)) {
        HILOG_ERROR("Force remove user directory path failed, errno %{public}d.", errno);
    }
}

/**
* @tc.name:    RemovedUserDeal001
* @tc.desc:    delete a user directory after the user is removed
* @tc.type:    FUNC
* @tc.require: issueI6DWHR
*/
HWTEST_F(WallpaperTest, RemovedUserDeal001, TestSize.Level0)
{
    std::shared_ptr<WallpaperService> wallpaperService = std::make_shared<WallpaperService>();
    ASSERT_EQ(WallpaperTest::SubscribeCommonEvent(wallpaperService), true);
    std::string commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_USER_ADDED;
    WallpaperTest::TriggerEvent(TEST_USERID, commonEvent);
    std::string userDir = WALLPAPER_DEFAULT_PATH + std::string("/") + std::to_string(TEST_USERID);
    ASSERT_EQ(FileDeal::IsDirExist(userDir), true);

    commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED;
    WallpaperTest::TriggerEvent(TEST_USERID, commonEvent);
    EXPECT_EQ(FileDeal::IsDirExist(userDir), false);
    if (!OHOS::ForceRemoveDirectory(userDir)) {
        HILOG_ERROR("Force remove user directory path failed, errno %{public}d.", errno);
    }
}

/**
* @tc.name:    SwitchedUserIdDeal001
* @tc.desc:    The wallpaper has changed after switched user
* @tc.type:    FUNC
* @tc.require: issueI6DWHR
*/
HWTEST_F(WallpaperTest, SwitchedUserIdDeal001, TestSize.Level0)
{
    std::shared_ptr<WallpaperService> wallpaperService = std::make_shared<WallpaperService>();
    wallpaperService->InitServiceHandler();
    ASSERT_EQ(WallpaperTest::SubscribeCommonEvent(wallpaperService), true);
    ApiInfo apiInfo{ false, false };
    std::vector<int32_t> ids;
    AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    int32_t beforeUserId = ids.empty() ? DEFAULT_USERID : ids[0];
    std::string addCommonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_USER_ADDED;
    WallpaperTest::TriggerEvent(TEST_USERID, addCommonEvent);
    std::string userDir = WALLPAPER_DEFAULT_PATH + std::string("/") + std::to_string(TEST_USERID);
    ASSERT_EQ(FileDeal::IsDirExist(userDir), true);
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().ResetWallpaper(LOCKSCREEN, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to reset lockscreen wallpaper";

    std::vector<uint64_t> oldLockscreenColor;
    wallpaperErrorCode = WallpaperManager::GetInstance().GetColors(LOCKSCREEN, apiInfo, oldLockscreenColor);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to GetColors";
    wallpaperErrorCode = WallpaperManager::GetInstance().ResetWallpaper(SYSTYEM, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to reset system wallpaper";
    std::vector<uint64_t> oldSystemColor;
    wallpaperErrorCode = WallpaperManager::GetInstance().GetColors(SYSTYEM, apiInfo, oldSystemColor);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to GetColors";

    std::string switchCommonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED;
    WallpaperTest::TriggerEvent(TEST_USERID, switchCommonEvent);
    wallpaperErrorCode = WallpaperManager::GetInstance().SetWallpaper(URI, LOCKSCREEN, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to set lockscreen wallpaper";
    std::vector<uint64_t> newLockscreenColor;
    wallpaperErrorCode = WallpaperManager::GetInstance().GetColors(LOCKSCREEN, apiInfo, newLockscreenColor);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to GetColors";
    wallpaperErrorCode = WallpaperManager::GetInstance().SetWallpaper(URI, SYSTYEM, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to set system wallpaper";
    std::vector<uint64_t> newSystemColor;
    wallpaperErrorCode = WallpaperManager::GetInstance().GetColors(SYSTYEM, apiInfo, newSystemColor);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to GetColors";
    EXPECT_NE(oldLockscreenColor, newLockscreenColor);
    EXPECT_NE(oldSystemColor, newSystemColor);

    WallpaperTest::TriggerEvent(beforeUserId, switchCommonEvent);
    std::string removeCommonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED;
    WallpaperTest::TriggerEvent(TEST_USERID, removeCommonEvent);
    EXPECT_EQ(FileDeal::IsDirExist(userDir), false);
    if (!OHOS::ForceRemoveDirectory(userDir)) {
        HILOG_ERROR("Force remove user directory path failed, errno %{public}d.", errno);
    }
}

/**
* @tc.name:    InvalidUserIdDeal001
* @tc.desc:    Invalid user id deal
* @tc.type:    FUNC
* @tc.require: issueI6DWHR
*/
HWTEST_F(WallpaperTest, InvalidUserIdDeal001, TestSize.Level0)
{
    std::shared_ptr<WallpaperService> wallpaperService = std::make_shared<WallpaperService>();
    wallpaperService->InitServiceHandler();
    ASSERT_EQ(WallpaperTest::SubscribeCommonEvent(wallpaperService), true);
    std::string commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_USER_ADDED;
    WallpaperTest::TriggerEvent(INVALID_USERID, commonEvent);
    std::string userDir = WALLPAPER_DEFAULT_PATH + std::string("/") + std::to_string(INVALID_USERID);
    EXPECT_EQ(FileDeal::IsDirExist(userDir), false);
    FileDeal::Mkdir(userDir);
    commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED;
    WallpaperTest::TriggerEvent(INVALID_USERID, commonEvent);
    EXPECT_EQ(FileDeal::IsDirExist(userDir), true);
    if (!OHOS::ForceRemoveDirectory(userDir)) {
        HILOG_ERROR("Force remove user directory path failed, errno %{public}d.", errno);
    }
}
/*********************   USER_DEAL   *********************/

/*********************   SetVideo    *********************/
/**
 * @tc.name:    SetVideo001
 * @tc.desc:    SetVideo input error fileType
 * @tc.type:    FUNC
 * @tc.require: issueI6R07J
 */
HWTEST_F(WallpaperTest, SetVideo001, TestSize.Level0)
{
    HILOG_INFO("SetVideo001 begin");
    ErrorCode ret = WallpaperManager::GetInstance().SetVideo(URI_30FPS_3S_MOV, SYSTYEM);
    EXPECT_EQ(ret, E_PARAMETERS_INVALID);
}

/**
 * @tc.name:    SetVideo002
 * @tc.desc:    SetVideo input error uri
 * @tc.type:    FUNC
 * @tc.require: issueI6R07J
 */
HWTEST_F(WallpaperTest, SetVideo002, TestSize.Level0)
{
    HILOG_INFO("SetVideo002 begin");
    std::string errUri = "errorPath/zm_30fps_4s.mp4";
    ErrorCode ret = WallpaperManager::GetInstance().SetVideo(errUri, SYSTYEM);
    EXPECT_EQ(ret, E_PARAMETERS_INVALID);
}

/**
 * @tc.name:    SetVideo003
 * @tc.desc:    SetVideo input correct parameter
 * @tc.type:    FUNC
 * @tc.require: issueI6R07J
 */
HWTEST_F(WallpaperTest, SetVideo003, TestSize.Level0)
{
    HILOG_INFO("SetVideo003 begin");
    ErrorCode ret = WallpaperManager::GetInstance().SetVideo(URI_30FPS_3S_MP4, SYSTYEM);
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name:    SetVideo004
 * @tc.desc:    SetVideo input error duration
 * @tc.type:    FUNC
 * @tc.require: issueI6R07J
 */
HWTEST_F(WallpaperTest, SetVideo004, TestSize.Level0)
{
    HILOG_INFO("SetVideo004 begin");
    ErrorCode ret = WallpaperManager::GetInstance().SetVideo(URI_15FPS_7S_MP4, SYSTYEM);
    EXPECT_EQ(ret, E_PARAMETERS_INVALID);
}

/**
 * @tc.name:    SetVideo005
 * @tc.desc:    SetVideo input error fileType
 * @tc.type:    FUNC
 * @tc.require: issueI6R07J
 */
HWTEST_F(WallpaperTest, SetVideo005, TestSize.Level0)
{
    HILOG_INFO("SetVideo005 begin");
    ErrorCode ret = WallpaperManager::GetInstance().SetVideo(URI_30FPS_3S_MOV, LOCKSCREEN);
    EXPECT_EQ(ret, E_PARAMETERS_INVALID);
}

/**
 * @tc.name:    SetVideo006
 * @tc.desc:    SetVideo input error uri
 * @tc.type:    FUNC
 * @tc.require: issueI6R07J
 */
HWTEST_F(WallpaperTest, SetVideo006, TestSize.Level0)
{
    HILOG_INFO("SetVideo006 begin");
    std::string errUri = "errorPath/zm_30fps_4s.mp4";
    ErrorCode ret = WallpaperManager::GetInstance().SetVideo(errUri, LOCKSCREEN);
    EXPECT_EQ(ret, E_PARAMETERS_INVALID);
}

/**
 * @tc.name:    SetVideo007
 * @tc.desc:    SetVideo input correct parameter
 * @tc.type:    FUNC
 * @tc.require: issueI6R07J
 */
HWTEST_F(WallpaperTest, SetVideo007, TestSize.Level0)
{
    HILOG_INFO("SetVideo007 begin");
    ErrorCode ret = WallpaperManager::GetInstance().SetVideo(URI_30FPS_3S_MP4, LOCKSCREEN);
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name:    SetVideo008
 * @tc.desc:    SetVideo input error duration
 * @tc.type:    FUNC
 * @tc.require: issueI6R07J
 */
HWTEST_F(WallpaperTest, SetVideo008, TestSize.Level0)
{
    HILOG_INFO("SetVideo008 begin");
    ErrorCode ret = WallpaperManager::GetInstance().SetVideo(URI_15FPS_7S_MP4, LOCKSCREEN);
    EXPECT_EQ(ret, E_PARAMETERS_INVALID);
}
/*********************   SetVideo    *********************/

/**
 * @tc.name:    SetCustomWallpaper001
 * @tc.desc:    Set a custom wallpaper in the Sceneborad scene
 * @tc.type:    FUNC
 * @tc.require: issueI7AAMU
 */
HWTEST_F(WallpaperTest, SetCustomWallpaper001, TestSize.Level0)
{
    HILOG_INFO("SetCustomWallpaper001 begin");
    ErrorCode testErrorCode = E_OK;
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        testErrorCode = E_NO_PERMISSION;
    }
    ErrorCode ret = WallpaperManager::GetInstance().SetCustomWallpaper(URI_ZIP, SYSTYEM);
    EXPECT_EQ(ret, testErrorCode);
    ret = WallpaperManager::GetInstance().SetCustomWallpaper(URI_ZIP, LOCKSCREEN);
    EXPECT_EQ(ret, testErrorCode);
}

/*********************   SendEvent    *********************/

/**
 * @tc.name:    SendEvent001
 * @tc.desc:    SetVideo input error fileType
 * @tc.type:    FUNC
 * @tc.require: issueI6R07J
 */
HWTEST_F(WallpaperTest, SendEvent001, TestSize.Level0)
{
    HILOG_INFO("SendEvent001 begin");
    std::string errEventType = "SHOW_ERROREVENTTYPE";
    ErrorCode ret = WallpaperManager::GetInstance().SendEvent("SHOW_ERROREVENTTYPE");
    EXPECT_EQ(ret, E_PARAMETERS_INVALID);
}

/**
 * @tc.name:    SendEvent002
 * @tc.desc:    SetVideo input error fileType
 * @tc.type:    FUNC
 * @tc.require: issueI6R07J
 */
HWTEST_F(WallpaperTest, SendEvent002, TestSize.Level0)
{
    HILOG_INFO("SendEvent002 begin");
    ErrorCode ret = WallpaperManager::GetInstance().SendEvent("SHOW_SYSTEMSCREEN");
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name:    SendEvent003
 * @tc.desc:    SetVideo input error fileType
 * @tc.type:    FUNC
 * @tc.require: issueI6R07J
 */
HWTEST_F(WallpaperTest, SendEvent003, TestSize.Level0)
{
    HILOG_INFO("SendEvent003 begin");
    ErrorCode ret = WallpaperManager::GetInstance().SendEvent("SHOW_LOCKSCREEN");
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name:    WallpaperTest_001
 * @tc.desc:    Test Onstop and OnStart.
 * @tc.type:    FUNC
 * @tc.require: issueI7OUB6
 */
HWTEST_F(WallpaperTest, WallpaperTest_001, TestSize.Level0)
{
    HILOG_INFO("Test Onstop");
    std::shared_ptr<WallpaperService> wallpaperService = std::make_shared<WallpaperService>();
    wallpaperService->state_ = WallpaperService::ServiceRunningState::STATE_RUNNING;
    wallpaperService->OnStop();
    EXPECT_EQ(wallpaperService->state_, WallpaperService::ServiceRunningState::STATE_NOT_START);
}

/**
 * @tc.name:    GetPictureFileName_001
 * @tc.desc:    Load userIds that are not found in the Map.
 * @tc.type:    FUNC
 * @tc.require: issueI90IUI
 */
HWTEST_F(WallpaperTest, GetPictureFileName_001, TestSize.Level0)
{
    HILOG_INFO("GetPictureFileName_001 begin");
    std::shared_ptr<WallpaperService> wallpaperService = std::make_shared<WallpaperService>();
    std::string fileName;
    wallpaperService->GetPictureFileName(TEST_USERID1, WALLPAPER_SYSTEM, fileName);
    auto wallpaperDefault = fileName.find(WALLPAPER_DEFAULT);
    auto homeWallpaper = fileName.find(HOME_WALLPAPER);
    EXPECT_EQ((wallpaperDefault != string::npos) || (homeWallpaper != string::npos), true);
    wallpaperService->SetWallpaperBackupData(TEST_USERID1, PICTURE, URI, WALLPAPER_SYSTEM);
    wallpaperService->GetPictureFileName(TEST_USERID1, WALLPAPER_SYSTEM, fileName);
    auto pos = fileName.find(to_string(TEST_USERID1));
    EXPECT_NE(pos, string::npos);
    wallpaperService->OnRemovedUser(TEST_USERID1);
}

/**
 * @tc.name:    RegisterWallpaperCallback_001
 * @tc.desc:    Test RegisterWallpaperCallback
 * @tc.type:    FUNC
 * @tc.require: issueIA87VK
 */
HWTEST_F(WallpaperTest, RegisterWallpaperCallback_001, TestSize.Level0)
{
    HILOG_INFO("RegisterWallpaperCallback_001 begin");
    JScallback callback = &WallpaperTest::TestCallBack;
    bool res = WallpaperManager::GetInstance().RegisterWallpaperCallback(callback);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name:    RegisterWallpaperListener_001
 * @tc.desc:    Test RegisterWallpaperListener
 * @tc.type:    FUNC
 * @tc.require: issueIA87VK
 */
HWTEST_F(WallpaperTest, RegisterWallpaperListener_001, TestSize.Level0)
{
    HILOG_INFO("RegisterWallpaperListener_001 begin");
    bool res = WallpaperManager::GetInstance().RegisterWallpaperListener();
    EXPECT_EQ(res, true);
}

/*********************   SetAllWallpapers   *********************/
/**
* @tc.name: SetAllWallpapers001
* @tc.desc: SetAllWallpapers normal device with wallpaperType[0]
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, SetAllWallpapers001, TestSize.Level0)
{
    HILOG_INFO("SetAllWallpapers001 begin");
    std::vector<WallpaperInfo> wallpaperInfo;
    wallpaperInfo.push_back(wallpaperInfo_normal_port);
    wallpaperInfo.push_back(wallpaperInfo_normal_land);
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().SetAllWallpapers(wallpaperInfo, SYSTYEM);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to SetAllWallpapers";
}

/**
* @tc.name: SetAllWallpapers002
* @tc.desc: SetAllWallpapers normal device with wallpaperType[1]
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, SetAllWallpapers002, TestSize.Level0)
{
    HILOG_INFO("SetAllWallpapers002 begin");
    std::vector<WallpaperInfo> wallpaperInfo;
    wallpaperInfo.push_back(wallpaperInfo_normal_port);
    wallpaperInfo.push_back(wallpaperInfo_normal_land);
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().SetAllWallpapers(wallpaperInfo, LOCKSCREEN);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to SetAllWallpapers";
}

/**
* @tc.name: SetAllWallpapers003
* @tc.desc: SetAllWallpapers unfold_1 device with wallpaperType[0]
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, SetAllWallpapers003, TestSize.Level0)
{
    HILOG_INFO("SetAllWallpapers003 begin");
    std::vector<WallpaperInfo> wallpaperInfo;
    wallpaperInfo.push_back(wallpaperInfo_normal_port);
    wallpaperInfo.push_back(wallpaperInfo_normal_land);
    wallpaperInfo.push_back(wallpaperInfo_unfold1_port);
    wallpaperInfo.push_back(wallpaperInfo_unfold1_land);
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().SetAllWallpapers(wallpaperInfo, SYSTYEM);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to SetAllWallpapers";
}

/**
* @tc.name: SetAllWallpapers004
* @tc.desc: SetAllWallpapers unfold_1 device with wallpaperType[1]
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, SetAllWallpapers004, TestSize.Level0)
{
    HILOG_INFO("SetAllWallpapers004 begin");
    std::vector<WallpaperInfo> wallpaperInfo;
    wallpaperInfo.push_back(wallpaperInfo_normal_port);
    wallpaperInfo.push_back(wallpaperInfo_normal_land);
    wallpaperInfo.push_back(wallpaperInfo_unfold1_port);
    wallpaperInfo.push_back(wallpaperInfo_unfold1_land);
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().SetAllWallpapers(wallpaperInfo, LOCKSCREEN);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to SetAllWallpapers";
}

/**
* @tc.name: SetAllWallpapers005
* @tc.desc: SetAllWallpapers unfold_2 device with wallpaperType[0]
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, SetAllWallpapers005, TestSize.Level0)
{
    HILOG_INFO("SetAllWallpapers005 begin");
    std::vector<WallpaperInfo> wallpaperInfo;
    wallpaperInfo.push_back(wallpaperInfo_normal_port);
    wallpaperInfo.push_back(wallpaperInfo_normal_land);
    wallpaperInfo.push_back(wallpaperInfo_unfold1_port);
    wallpaperInfo.push_back(wallpaperInfo_unfold1_land);
    wallpaperInfo.push_back(wallpaperInfo_unfold2_port);
    wallpaperInfo.push_back(wallpaperInfo_unfold2_land);
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().SetAllWallpapers(wallpaperInfo, SYSTYEM);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to SetAllWallpapers";
}

/**
* @tc.name: SetAllWallpapers006
* @tc.desc: SetAllWallpapers unfold_2 device with wallpaperType[1]
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, SetAllWallpapers006, TestSize.Level0)
{
    HILOG_INFO("SetAllWallpapers006 begin");
    std::vector<WallpaperInfo> wallpaperInfo;
    wallpaperInfo.push_back(wallpaperInfo_normal_port);
    wallpaperInfo.push_back(wallpaperInfo_normal_land);
    wallpaperInfo.push_back(wallpaperInfo_unfold1_port);
    wallpaperInfo.push_back(wallpaperInfo_unfold1_land);
    wallpaperInfo.push_back(wallpaperInfo_unfold2_port);
    wallpaperInfo.push_back(wallpaperInfo_unfold2_land);
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().SetAllWallpapers(wallpaperInfo, LOCKSCREEN);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to SetAllWallpapers";
}

/*********************   SetAllWallpapers   *********************/

/*********************   GetCorrespondWallpaper   *********************/
/**
* @tc.name:   GetCorrespondWallpaper001
* @tc.desc:   GetCorrespondWallpaper normal device with wallpaperType[0].
* @tc.type:    FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, GetCorrespondWallpaper001, TestSize.Level0)
{
    HILOG_INFO("GetCorrespondWallpaper001  begin");
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap;
    ErrorCode wallpaperErrorCode =
        WallpaperManager::GetInstance().GetCorrespondWallpaper(SYSTYEM, NORMAL, PORT, pixelMap);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to GetCorrespondWallpaper";
    wallpaperErrorCode = WallpaperManager::GetInstance().GetCorrespondWallpaper(SYSTYEM, NORMAL, LAND, pixelMap);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to GetCorrespondWallpaper";
}

/**
* @tc.name:   GetCorrespondWallpaper002
* @tc.desc:   GetCorrespondWallpaper normal device with wallpaperType[1].
* @tc.type:    FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, GetCorrespondWallpaper002, TestSize.Level0)
{
    HILOG_INFO("GetPixelMap002  begin");
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap;
    ErrorCode wallpaperErrorCode =
        WallpaperManager::GetInstance().GetCorrespondWallpaper(LOCKSCREEN, NORMAL, PORT, pixelMap);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to GetCorrespondWallpaper";
    wallpaperErrorCode = WallpaperManager::GetInstance().GetCorrespondWallpaper(LOCKSCREEN, NORMAL, LAND, pixelMap);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to GetCorrespondWallpaper";
}

/**
* @tc.name:   GetCorrespondWallpaper003
* @tc.desc:   GetCorrespondWallpaper unfold_1 device with wallpaperType[0].
* @tc.type:    FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, GetCorrespondWallpaper003, TestSize.Level0)
{
    HILOG_INFO("GetCorrespondWallpaper003  begin");
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap;
    ErrorCode wallpaperErrorCode =
        WallpaperManager::GetInstance().GetCorrespondWallpaper(SYSTYEM, UNFOLD_1, PORT, pixelMap);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to GetCorrespondWallpaper";
    wallpaperErrorCode = WallpaperManager::GetInstance().GetCorrespondWallpaper(SYSTYEM, UNFOLD_1, LAND, pixelMap);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to GetCorrespondWallpaper";
}

/**
* @tc.name:   GetCorrespondWallpaper004
* @tc.desc:   GetCorrespondWallpaper unfold_1 device with wallpaperType[1].
* @tc.type:    FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, GetCorrespondWallpaper004, TestSize.Level0)
{
    HILOG_INFO("GetCorrespondWallpaper004  begin");
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap;
    ErrorCode wallpaperErrorCode =
        WallpaperManager::GetInstance().GetCorrespondWallpaper(LOCKSCREEN, UNFOLD_1, PORT, pixelMap);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to GetCorrespondWallpaper";
    wallpaperErrorCode = WallpaperManager::GetInstance().GetCorrespondWallpaper(LOCKSCREEN, UNFOLD_1, LAND, pixelMap);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to GetCorrespondWallpaper";
}

/**
* @tc.name:   GetCorrespondWallpaper005
* @tc.desc:   GetCorrespondWallpaper unfold_2 device with wallpaperType[0].
* @tc.type:    FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, GetCorrespondWallpaper005, TestSize.Level0)
{
    HILOG_INFO("GetCorrespondWallpaper005  begin");
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap;
    ErrorCode wallpaperErrorCode =
        WallpaperManager::GetInstance().GetCorrespondWallpaper(SYSTYEM, UNFOLD_2, PORT, pixelMap);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to GetCorrespondWallpaper";
    wallpaperErrorCode = WallpaperManager::GetInstance().GetCorrespondWallpaper(SYSTYEM, UNFOLD_2, LAND, pixelMap);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to GetCorrespondWallpaper";
}

/**
* @tc.name:   GetCorrespondWallpaper006
* @tc.desc:   GetCorrespondWallpaper unfold_2 device with wallpaperType[1].
* @tc.type:    FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, GetCorrespondWallpaper006, TestSize.Level0)
{
    HILOG_INFO("GetCorrespondWallpaper006  begin");
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap;
    ErrorCode wallpaperErrorCode =
        WallpaperManager::GetInstance().GetCorrespondWallpaper(LOCKSCREEN, UNFOLD_2, PORT, pixelMap);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to GetCorrespondWallpaper";
    wallpaperErrorCode = WallpaperManager::GetInstance().GetCorrespondWallpaper(LOCKSCREEN, UNFOLD_2, LAND, pixelMap);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to GetCorrespondWallpaper";
}
/*********************   GetCorrespondWallpaper   *********************/

/*********************   Wallpaper_Inner_Api   *********************/
/**
* @tc.name:   IsDefaultWallpaperResource
* @tc.desc:   IsDefaultWallpaperResource wallpaper resource is empty.
* @tc.type:    FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, IsDefaultWallpaperResource001, TestSize.Level0)
{
    HILOG_INFO("IsDefaultWallpaperResource001  begin");
    std::shared_ptr<WallpaperService> wallpaperService = std::make_shared<WallpaperService>();
    int32_t userId = wallpaperService->QueryActiveUserId();
    ApiInfo apiInfo{ false, false };
    std::vector<WallpaperInfo> wallpaperInfo;
    wallpaperInfo.push_back(wallpaperInfo_normal_port);
    wallpaperInfo.push_back(wallpaperInfo_normal_land);
    wallpaperInfo.push_back(wallpaperInfo_unfold1_port);
    wallpaperInfo.push_back(wallpaperInfo_unfold1_land);
    wallpaperInfo.push_back(wallpaperInfo_unfold2_port);
    wallpaperInfo.push_back(wallpaperInfo_unfold2_land);
    ErrorCode wallpaperErrorCode = WallpaperManager::GetInstance().ResetWallpaper(SYSTYEM, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to reset lockscreen wallpaper";
    auto ret = WallpaperManagerClient::GetInstance().IsDefaultWallpaperResource(userId, SYSTYEM);
    EXPECT_EQ(ret, true) << "Failed to IsDefaultWallpaperResource";
    wallpaperErrorCode = WallpaperManager::GetInstance().SetAllWallpapers(wallpaperInfo, SYSTYEM);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to set system wallpaper";
    ret = WallpaperManagerClient::GetInstance().IsDefaultWallpaperResource(userId, SYSTYEM);
    EXPECT_EQ(ret, false) << "Failed to IsDefaultWallpaperResource";
    wallpaperErrorCode = WallpaperManager::GetInstance().ResetWallpaper(LOCKSCREEN, apiInfo);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to reset lockscreen wallpaper";
    ret = WallpaperManagerClient::GetInstance().IsDefaultWallpaperResource(userId, LOCKSCREEN);
    EXPECT_EQ(ret, true) << "Failed to IsDefaultWallpaperResource";
    wallpaperErrorCode = WallpaperManager::GetInstance().SetAllWallpapers(wallpaperInfo, LOCKSCREEN);
    EXPECT_EQ(wallpaperErrorCode, E_OK) << "Failed to set system wallpaper";
    ret = WallpaperManagerClient::GetInstance().IsDefaultWallpaperResource(userId, SYSTYEM);
    EXPECT_EQ(ret, false) << "Failed to IsDefaultWallpaperResource";
}

/**
* @tc.name:   SetAllWallpapers
* @tc.desc:   SetAllWallpapers unfold_2 device with wallpaperType[0].
* @tc.type:    FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, SetAllWallpapersClient001, TestSize.Level0)
{
    HILOG_INFO("SetAllWallpapersClient001  begin");
    std::vector<WallpaperInfo> wallpaperInfo;
    wallpaperInfo.push_back(wallpaperInfo_normal_port);
    wallpaperInfo.push_back(wallpaperInfo_normal_land);
    wallpaperInfo.push_back(wallpaperInfo_unfold1_port);
    wallpaperInfo.push_back(wallpaperInfo_unfold1_land);
    wallpaperInfo.push_back(wallpaperInfo_unfold2_port);
    wallpaperInfo.push_back(wallpaperInfo_unfold2_land);
    auto ret = WallpaperManagerClient::GetInstance().SetAllWallpapers(wallpaperInfo, SYSTYEM);
    EXPECT_EQ(ret, static_cast<int32_t>(E_OK)) << "Failed to SetAllWallpapers";
}

/**
* @tc.name: SetAllWallpapers
* @tc.desc: SetAllWallpapers unfold_2 device with wallpaperType[1]
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(WallpaperTest, SetAllWallpapersClient002, TestSize.Level0)
{
    HILOG_INFO("SetAllWallpapersClient002 begin");
    std::vector<WallpaperInfo> wallpaperInfo;
    wallpaperInfo.push_back(wallpaperInfo_normal_port);
    wallpaperInfo.push_back(wallpaperInfo_normal_land);
    wallpaperInfo.push_back(wallpaperInfo_unfold1_port);
    wallpaperInfo.push_back(wallpaperInfo_unfold1_land);
    wallpaperInfo.push_back(wallpaperInfo_unfold2_port);
    wallpaperInfo.push_back(wallpaperInfo_unfold2_land);
    auto ret = WallpaperManagerClient::GetInstance().SetAllWallpapers(wallpaperInfo, LOCKSCREEN);
    EXPECT_EQ(ret, static_cast<int32_t>(E_OK)) << "Failed to SetAllWallpapers";
}
/*********************   Wallpaper_Inner_Api   *********************/
} // namespace WallpaperMgrService
} // namespace OHOS