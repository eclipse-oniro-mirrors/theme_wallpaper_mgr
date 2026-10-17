/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <vector>

#include "message_parcel.h"
#include "wallpaper_common.h"
#include "wallpaper_manager_common_info.h"
#include "wallpaper_picture_info_by_parcel.h"

using namespace testing::ext;
namespace OHOS {
namespace WallpaperMgrService {
namespace {
constexpr int32_t VECTOR_MAX_SIZE = 6;
constexpr int32_t INVALID_FOLD_STATE = 99;
constexpr int32_t INVALID_ROTATE_STATE = 99;
constexpr int32_t TEST_LENGTH = 128;
constexpr const char *TMP_FILE_PATH = "/data/local/tmp/wallpaper_pic_info_ut.tmp";

int32_t CreateValidFd()
{
    return open(TMP_FILE_PATH, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
}

void WriteVectorSize(MessageParcel &parcel, int32_t vectorSize)
{
    parcel.WriteInt32(vectorSize);
}

void WriteItem(MessageParcel &parcel, int32_t foldState, int32_t rotateState, int32_t fd, int32_t length)
{
    parcel.WriteInt32(foldState);
    parcel.WriteInt32(rotateState);
    parcel.WriteFileDescriptor(fd);
    parcel.WriteInt32(length);
}

void WriteItemNoFd(MessageParcel &parcel, int32_t foldState, int32_t rotateState)
{
    parcel.WriteInt32(foldState);
    parcel.WriteInt32(rotateState);
}

WallpaperPictureInfo MakeItem(FoldState foldState, RotateState rotateState, int32_t fd, int32_t length)
{
    WallpaperPictureInfo item;
    item.foldState = foldState;
    item.rotateState = rotateState;
    item.fd = fd;
    item.length = length;
    return item;
}
} // namespace

class WallpaperPictureInfoByParcelTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
    }
    static void TearDownTestCase(void)
    {
    }
    void SetUp()
    {
    }
    void TearDown()
    {
    }
};

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Marshalling_EmptyVector_001
 * @tc.desc: Marshalling with empty vector, for-loop body not executed.
 * @tc.type: FUNC
 */
HWTEST_F(
    WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Marshalling_EmptyVector_001, TestSize.Level1)
{
    WallpaperPictureInfoByParcel info;
    MessageParcel parcel;
    EXPECT_TRUE(info.Marshalling(parcel));
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Marshalling_NonEmptyVector_001
 * @tc.desc: Marshalling with non-empty vector, for-loop body executed.
 * @tc.type: FUNC
 */
HWTEST_F(
    WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Marshalling_NonEmptyVector_001, TestSize.Level1)
{
    int32_t fd = CreateValidFd();
    ASSERT_GE(fd, 0);
    WallpaperPictureInfoByParcel info;
    info.wallpaperPictureInfo_.push_back(MakeItem(FoldState::NORMAL, RotateState::PORT, fd, TEST_LENGTH));
    MessageParcel parcel;
    EXPECT_TRUE(info.Marshalling(parcel));
    close(fd);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Unmarshalling_VectorSizeTooLarge_001
 * @tc.desc: Unmarshalling with vectorSize > VECTOR_MAX_SIZE, return nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Unmarshalling_VectorSizeTooLarge_001,
    TestSize.Level1)
{
    MessageParcel parcel;
    WriteVectorSize(parcel, VECTOR_MAX_SIZE + 1);
    auto *obj = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    EXPECT_EQ(obj, nullptr);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Unmarshalling_VectorSizeNegative_001
 * @tc.desc: Unmarshalling with vectorSize < VECTOR_MIN_SIZE, return nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Unmarshalling_VectorSizeNegative_001,
    TestSize.Level1)
{
    MessageParcel parcel;
    WriteVectorSize(parcel, -1);
    auto *obj = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    EXPECT_EQ(obj, nullptr);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Unmarshalling_VectorSizeZero_001
 * @tc.desc: Unmarshalling with vectorSize == 0, for-loop not executed, return valid obj.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Unmarshalling_VectorSizeZero_001,
    TestSize.Level1)
{
    MessageParcel parcel;
    WriteVectorSize(parcel, 0);
    auto *obj = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    ASSERT_NE(obj, nullptr);
    EXPECT_TRUE(obj->wallpaperPictureInfo_.empty());
    delete obj;
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Unmarshalling_FoldNormalRotatePort_001
 * @tc.desc: Unmarshalling success path, foldState==NORMAL && rotateState==PORT && fd valid.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Unmarshalling_FoldNormalRotatePort_001,
    TestSize.Level1)
{
    int32_t fd = CreateValidFd();
    ASSERT_GE(fd, 0);
    MessageParcel parcel;
    WriteVectorSize(parcel, 1);
    WriteItem(
        parcel, static_cast<int32_t>(FoldState::NORMAL), static_cast<int32_t>(RotateState::PORT), fd, TEST_LENGTH);
    auto *obj = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    ASSERT_NE(obj, nullptr);
    ASSERT_EQ(obj->wallpaperPictureInfo_.size(), 1u);
    EXPECT_EQ(obj->wallpaperPictureInfo_[0].foldState, FoldState::NORMAL);
    EXPECT_EQ(obj->wallpaperPictureInfo_[0].rotateState, RotateState::PORT);
    EXPECT_GE(obj->wallpaperPictureInfo_[0].fd, 0);
    EXPECT_EQ(obj->wallpaperPictureInfo_[0].length, TEST_LENGTH);
    WallpaperPictureInfoByParcel::CloseWallpaperInfoFd(obj->wallpaperPictureInfo_);
    delete obj;
    close(fd);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Unmarshalling_FoldUnfold1_001
 * @tc.desc: Unmarshalling success path, foldState==UNFOLD_1 branch.
 * @tc.type: FUNC
 */
HWTEST_F(
    WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Unmarshalling_FoldUnfold1_001, TestSize.Level1)
{
    int32_t fd = CreateValidFd();
    ASSERT_GE(fd, 0);
    MessageParcel parcel;
    WriteVectorSize(parcel, 1);
    WriteItem(
        parcel, static_cast<int32_t>(FoldState::UNFOLD_1), static_cast<int32_t>(RotateState::PORT), fd, TEST_LENGTH);
    auto *obj = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    ASSERT_NE(obj, nullptr);
    ASSERT_EQ(obj->wallpaperPictureInfo_.size(), 1u);
    EXPECT_EQ(obj->wallpaperPictureInfo_[0].foldState, FoldState::UNFOLD_1);
    WallpaperPictureInfoByParcel::CloseWallpaperInfoFd(obj->wallpaperPictureInfo_);
    delete obj;
    close(fd);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Unmarshalling_FoldUnfold2_001
 * @tc.desc: Unmarshalling success path, foldState==UNFOLD_2 branch.
 * @tc.type: FUNC
 */
HWTEST_F(
    WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Unmarshalling_FoldUnfold2_001, TestSize.Level1)
{
    int32_t fd = CreateValidFd();
    ASSERT_GE(fd, 0);
    MessageParcel parcel;
    WriteVectorSize(parcel, 1);
    WriteItem(
        parcel, static_cast<int32_t>(FoldState::UNFOLD_2), static_cast<int32_t>(RotateState::PORT), fd, TEST_LENGTH);
    auto *obj = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    ASSERT_NE(obj, nullptr);
    ASSERT_EQ(obj->wallpaperPictureInfo_.size(), 1u);
    EXPECT_EQ(obj->wallpaperPictureInfo_[0].foldState, FoldState::UNFOLD_2);
    WallpaperPictureInfoByParcel::CloseWallpaperInfoFd(obj->wallpaperPictureInfo_);
    delete obj;
    close(fd);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Unmarshalling_RotateLand_001
 * @tc.desc: Unmarshalling success path, rotateState==LAND branch.
 * @tc.type: FUNC
 */
HWTEST_F(
    WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Unmarshalling_RotateLand_001, TestSize.Level1)
{
    int32_t fd = CreateValidFd();
    ASSERT_GE(fd, 0);
    MessageParcel parcel;
    WriteVectorSize(parcel, 1);
    WriteItem(
        parcel, static_cast<int32_t>(FoldState::NORMAL), static_cast<int32_t>(RotateState::LAND), fd, TEST_LENGTH);
    auto *obj = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    ASSERT_NE(obj, nullptr);
    ASSERT_EQ(obj->wallpaperPictureInfo_.size(), 1u);
    EXPECT_EQ(obj->wallpaperPictureInfo_[0].rotateState, RotateState::LAND);
    WallpaperPictureInfoByParcel::CloseWallpaperInfoFd(obj->wallpaperPictureInfo_);
    delete obj;
    close(fd);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Unmarshalling_InvalidFoldState_001
 * @tc.desc: Unmarshalling with invalid foldState, return nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Unmarshalling_InvalidFoldState_001,
    TestSize.Level1)
{
    MessageParcel parcel;
    WriteVectorSize(parcel, 1);
    WriteItemNoFd(parcel, INVALID_FOLD_STATE, static_cast<int32_t>(RotateState::PORT));
    auto *obj = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    EXPECT_EQ(obj, nullptr);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Unmarshalling_InvalidRotateState_001
 * @tc.desc: Unmarshalling with invalid rotateState, return nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Unmarshalling_InvalidRotateState_001,
    TestSize.Level1)
{
    MessageParcel parcel;
    WriteVectorSize(parcel, 1);
    WriteItemNoFd(parcel, static_cast<int32_t>(FoldState::NORMAL), INVALID_ROTATE_STATE);
    auto *obj = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    EXPECT_EQ(obj, nullptr);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Unmarshalling_InvalidFd_001
 * @tc.desc: Unmarshalling with ReadFileDescriptor fail (fd < 0), return nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(
    WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Unmarshalling_InvalidFd_001, TestSize.Level1)
{
    MessageParcel parcel;
    WriteVectorSize(parcel, 1);
    WriteItemNoFd(parcel, static_cast<int32_t>(FoldState::NORMAL), static_cast<int32_t>(RotateState::PORT));
    auto *obj = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    EXPECT_EQ(obj, nullptr);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Unmarshalling_MultiItemsFdFail_001
 * @tc.desc: Unmarshalling with first item valid and second item fd invalid, CloseWallpaperInfoFd closes prior fd.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Unmarshalling_MultiItemsFdFail_001,
    TestSize.Level1)
{
    int32_t fd = CreateValidFd();
    ASSERT_GE(fd, 0);
    MessageParcel parcel;
    WriteVectorSize(parcel, 2);
    WriteItem(
        parcel, static_cast<int32_t>(FoldState::NORMAL), static_cast<int32_t>(RotateState::PORT), fd, TEST_LENGTH);
    WriteItemNoFd(parcel, static_cast<int32_t>(FoldState::UNFOLD_1), static_cast<int32_t>(RotateState::LAND));
    auto *obj = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    EXPECT_EQ(obj, nullptr);
    close(fd);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_CloseWallpaperInfoFd_Empty_001
 * @tc.desc: CloseWallpaperInfoFd with empty vector, for-loop not executed.
 * @tc.type: FUNC
 */
HWTEST_F(
    WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_CloseWallpaperInfoFd_Empty_001, TestSize.Level1)
{
    std::vector<WallpaperPictureInfo> infos;
    WallpaperPictureInfoByParcel::CloseWallpaperInfoFd(infos);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_CloseWallpaperInfoFd_InvalidFd_001
 * @tc.desc: CloseWallpaperInfoFd with fd < 0, the close branch not taken.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_CloseWallpaperInfoFd_InvalidFd_001,
    TestSize.Level1)
{
    WallpaperPictureInfo item = MakeItem(FoldState::NORMAL, RotateState::PORT, -1, 0);
    std::vector<WallpaperPictureInfo> infos;
    infos.push_back(item);
    WallpaperPictureInfoByParcel::CloseWallpaperInfoFd(infos);
    EXPECT_EQ(infos[0].fd, -1);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_CloseWallpaperInfoFd_ValidFd_001
 * @tc.desc: CloseWallpaperInfoFd with valid fd (fd >= 0), the close branch taken.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_CloseWallpaperInfoFd_ValidFd_001,
    TestSize.Level1)
{
    int32_t fd = CreateValidFd();
    ASSERT_GE(fd, 0);
    WallpaperPictureInfo item = MakeItem(FoldState::NORMAL, RotateState::PORT, fd, TEST_LENGTH);
    std::vector<WallpaperPictureInfo> infos;
    infos.push_back(item);
    WallpaperPictureInfoByParcel::CloseWallpaperInfoFd(infos);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Marshalling_InvalidFd_001
 * @tc.desc: Marshalling with invalid fd (-1), WriteFileDescriptor fails, status=false, return false.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Marshalling_InvalidFd_001, TestSize.Level1)
{
    WallpaperPictureInfoByParcel info;
    info.wallpaperPictureInfo_.push_back(MakeItem(FoldState::NORMAL, RotateState::PORT, -1, TEST_LENGTH));
    MessageParcel parcel;
    EXPECT_FALSE(info.Marshalling(parcel));
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Marshalling_MultiItems_001
 * @tc.desc: Marshalling with 2 valid items, for-loop iterates twice, return true.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Marshalling_MultiItems_001, TestSize.Level1)
{
    int32_t fd1 = CreateValidFd();
    ASSERT_GE(fd1, 0);
    int32_t fd2 = CreateValidFd();
    ASSERT_GE(fd2, 0);
    WallpaperPictureInfoByParcel info;
    info.wallpaperPictureInfo_.push_back(MakeItem(FoldState::NORMAL, RotateState::PORT, fd1, TEST_LENGTH));
    info.wallpaperPictureInfo_.push_back(MakeItem(FoldState::UNFOLD_1, RotateState::LAND, fd2, TEST_LENGTH));
    MessageParcel parcel;
    EXPECT_TRUE(info.Marshalling(parcel));
    close(fd1);
    close(fd2);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Marshalling_MultiItemsOneInvalidFd_001
 * @tc.desc: Marshalling with 2 items, first invalid fd, status=false triggers break, second item not processed, return
 false.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Marshalling_MultiItemsOneInvalidFd_001,
    TestSize.Level1)
{
    int32_t fd = CreateValidFd();
    ASSERT_GE(fd, 0);
    WallpaperPictureInfoByParcel info;
    info.wallpaperPictureInfo_.push_back(MakeItem(FoldState::NORMAL, RotateState::PORT, -1, TEST_LENGTH));
    info.wallpaperPictureInfo_.push_back(MakeItem(FoldState::UNFOLD_1, RotateState::LAND, fd, TEST_LENGTH));
    MessageParcel parcel;
    EXPECT_FALSE(info.Marshalling(parcel));
    close(fd);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Unmarshalling_VectorSizeMax_001
 * @tc.desc: Unmarshalling with vectorSize == VECTOR_MAX_SIZE (boundary), all items valid, return obj.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Unmarshalling_VectorSizeMax_001,
    TestSize.Level1)
{
    int32_t fd = CreateValidFd();
    ASSERT_GE(fd, 0);
    MessageParcel parcel;
    WriteVectorSize(parcel, VECTOR_MAX_SIZE);
    for (int32_t i = 0; i < VECTOR_MAX_SIZE; i++) {
        WriteItem(
            parcel, static_cast<int32_t>(FoldState::NORMAL), static_cast<int32_t>(RotateState::PORT), fd, TEST_LENGTH);
    }
    auto *obj = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    ASSERT_NE(obj, nullptr);
    ASSERT_EQ(obj->wallpaperPictureInfo_.size(), static_cast<size_t>(VECTOR_MAX_SIZE));
    WallpaperPictureInfoByParcel::CloseWallpaperInfoFd(obj->wallpaperPictureInfo_);
    delete obj;
    close(fd);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Unmarshalling_MultiItemsSuccess_001
 * @tc.desc: Unmarshalling with 2 valid items, both push_back succeed, return obj.release().
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Unmarshalling_MultiItemsSuccess_001,
    TestSize.Level1)
{
    int32_t fd1 = CreateValidFd();
    ASSERT_GE(fd1, 0);
    int32_t fd2 = CreateValidFd();
    ASSERT_GE(fd2, 0);
    MessageParcel parcel;
    WriteVectorSize(parcel, 2);
    WriteItem(
        parcel, static_cast<int32_t>(FoldState::NORMAL), static_cast<int32_t>(RotateState::PORT), fd1, TEST_LENGTH);
    WriteItem(
        parcel, static_cast<int32_t>(FoldState::UNFOLD_1), static_cast<int32_t>(RotateState::LAND), fd2, TEST_LENGTH);
    auto *obj = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    ASSERT_NE(obj, nullptr);
    ASSERT_EQ(obj->wallpaperPictureInfo_.size(), 2u);
    EXPECT_EQ(obj->wallpaperPictureInfo_[0].foldState, FoldState::NORMAL);
    EXPECT_EQ(obj->wallpaperPictureInfo_[0].rotateState, RotateState::PORT);
    EXPECT_EQ(obj->wallpaperPictureInfo_[1].foldState, FoldState::UNFOLD_1);
    EXPECT_EQ(obj->wallpaperPictureInfo_[1].rotateState, RotateState::LAND);
    WallpaperPictureInfoByParcel::CloseWallpaperInfoFd(obj->wallpaperPictureInfo_);
    delete obj;
    close(fd1);
    close(fd2);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Unmarshalling_SecondItemInvalidFoldState_001
 * @tc.desc: Unmarshalling, first item valid, second item invalid foldState, CloseWallpaperInfoFd on prior, return
 * nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest,
    WallpaperPictureInfoByParcelTest_Unmarshalling_SecondItemInvalidFoldState_001, TestSize.Level1)
{
    int32_t fd = CreateValidFd();
    ASSERT_GE(fd, 0);
    MessageParcel parcel;
    WriteVectorSize(parcel, 2);
    WriteItem(
        parcel, static_cast<int32_t>(FoldState::NORMAL), static_cast<int32_t>(RotateState::PORT), fd, TEST_LENGTH);
    WriteItemNoFd(parcel, INVALID_FOLD_STATE, static_cast<int32_t>(RotateState::PORT));
    auto *obj = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    EXPECT_EQ(obj, nullptr);
    close(fd);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Unmarshalling_SecondItemInvalidRotateState_001
 * @tc.desc: Unmarshalling, first item valid, second item invalid rotateState, CloseWallpaperInfoFd on prior, return
 * nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest,
    WallpaperPictureInfoByParcelTest_Unmarshalling_SecondItemInvalidRotateState_001, TestSize.Level1)
{
    int32_t fd = CreateValidFd();
    ASSERT_GE(fd, 0);
    MessageParcel parcel;
    WriteVectorSize(parcel, 2);
    WriteItem(
        parcel, static_cast<int32_t>(FoldState::NORMAL), static_cast<int32_t>(RotateState::PORT), fd, TEST_LENGTH);
    WriteItemNoFd(parcel, static_cast<int32_t>(FoldState::UNFOLD_1), INVALID_ROTATE_STATE);
    auto *obj = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    EXPECT_EQ(obj, nullptr);
    close(fd);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_CloseWallpaperInfoFd_MixedFds_001
 * @tc.desc: CloseWallpaperInfoFd with mixed valid and invalid fds in same vector, both branches taken.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_CloseWallpaperInfoFd_MixedFds_001,
    TestSize.Level1)
{
    int32_t fd = CreateValidFd();
    ASSERT_GE(fd, 0);
    std::vector<WallpaperPictureInfo> infos;
    infos.push_back(MakeItem(FoldState::NORMAL, RotateState::PORT, fd, TEST_LENGTH));
    infos.push_back(MakeItem(FoldState::UNFOLD_1, RotateState::LAND, -1, 0));
    WallpaperPictureInfoByParcel::CloseWallpaperInfoFd(infos);
    EXPECT_EQ(infos[0].fd, -1);
    EXPECT_EQ(infos[1].fd, -1);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Marshalling_Unmarshalling_RoundTrip_001
 * @tc.desc: Marshalling then Unmarshalling from same parcel, verify data integrity (UNFOLD_2 + LAND).
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest, WallpaperPictureInfoByParcelTest_Marshalling_Unmarshalling_RoundTrip_001,
    TestSize.Level1)
{
    int32_t fd = CreateValidFd();
    ASSERT_GE(fd, 0);
    WallpaperPictureInfoByParcel src;
    src.wallpaperPictureInfo_.push_back(MakeItem(FoldState::UNFOLD_2, RotateState::LAND, fd, TEST_LENGTH));
    MessageParcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));
    auto *dst = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    ASSERT_NE(dst, nullptr);
    ASSERT_EQ(dst->wallpaperPictureInfo_.size(), 1u);
    EXPECT_EQ(dst->wallpaperPictureInfo_[0].foldState, FoldState::UNFOLD_2);
    EXPECT_EQ(dst->wallpaperPictureInfo_[0].rotateState, RotateState::LAND);
    EXPECT_EQ(dst->wallpaperPictureInfo_[0].length, TEST_LENGTH);
    WallpaperPictureInfoByParcel::CloseWallpaperInfoFd(dst->wallpaperPictureInfo_);
    delete dst;
    close(fd);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Marshalling_SecondItemInvalidFd_001
 * @tc.desc: Marshalling with 2 items, first valid, second invalid fd, first iteration !status=false, second iteration
 * !status=true triggers break, return false.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest,
    WallpaperPictureInfoByParcelTest_Marshalling_SecondItemInvalidFd_001, TestSize.Level1)
{
    int32_t fd = CreateValidFd();
    ASSERT_GE(fd, 0);
    WallpaperPictureInfoByParcel info;
    info.wallpaperPictureInfo_.push_back(MakeItem(FoldState::NORMAL, RotateState::PORT, fd, TEST_LENGTH));
    info.wallpaperPictureInfo_.push_back(MakeItem(FoldState::UNFOLD_1, RotateState::LAND, -1, TEST_LENGTH));
    MessageParcel parcel;
    EXPECT_FALSE(info.Marshalling(parcel));
    close(fd);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Unmarshalling_FoldUnfold1RotateLand_001
 * @tc.desc: Unmarshalling success path, foldState==UNFOLD_1 && rotateState==LAND.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest,
    WallpaperPictureInfoByParcelTest_Unmarshalling_FoldUnfold1RotateLand_001, TestSize.Level1)
{
    int32_t fd = CreateValidFd();
    ASSERT_GE(fd, 0);
    MessageParcel parcel;
    WriteVectorSize(parcel, 1);
    WriteItem(
        parcel, static_cast<int32_t>(FoldState::UNFOLD_1), static_cast<int32_t>(RotateState::LAND), fd, TEST_LENGTH);
    auto *obj = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    ASSERT_NE(obj, nullptr);
    ASSERT_EQ(obj->wallpaperPictureInfo_.size(), 1u);
    EXPECT_EQ(obj->wallpaperPictureInfo_[0].foldState, FoldState::UNFOLD_1);
    EXPECT_EQ(obj->wallpaperPictureInfo_[0].rotateState, RotateState::LAND);
    WallpaperPictureInfoByParcel::CloseWallpaperInfoFd(obj->wallpaperPictureInfo_);
    delete obj;
    close(fd);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_Unmarshalling_FoldUnfold2RotateLand_001
 * @tc.desc: Unmarshalling success path, foldState==UNFOLD_2 && rotateState==LAND.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest,
    WallpaperPictureInfoByParcelTest_Unmarshalling_FoldUnfold2RotateLand_001, TestSize.Level1)
{
    int32_t fd = CreateValidFd();
    ASSERT_GE(fd, 0);
    MessageParcel parcel;
    WriteVectorSize(parcel, 1);
    WriteItem(
        parcel, static_cast<int32_t>(FoldState::UNFOLD_2), static_cast<int32_t>(RotateState::LAND), fd, TEST_LENGTH);
    auto *obj = WallpaperPictureInfoByParcel::Unmarshalling(parcel);
    ASSERT_NE(obj, nullptr);
    ASSERT_EQ(obj->wallpaperPictureInfo_.size(), 1u);
    EXPECT_EQ(obj->wallpaperPictureInfo_[0].foldState, FoldState::UNFOLD_2);
    EXPECT_EQ(obj->wallpaperPictureInfo_[0].rotateState, RotateState::LAND);
    WallpaperPictureInfoByParcel::CloseWallpaperInfoFd(obj->wallpaperPictureInfo_);
    delete obj;
    close(fd);
    unlink(TMP_FILE_PATH);
}

/**
 * @tc.name: WallpaperPictureInfoByParcelTest_CloseWallpaperInfoFd_MultipleValidFds_001
 * @tc.desc: CloseWallpaperInfoFd with 2 valid fds, close branch (fd >= 0) taken multiple times in same loop.
 * @tc.type: FUNC
 */
HWTEST_F(WallpaperPictureInfoByParcelTest,
    WallpaperPictureInfoByParcelTest_CloseWallpaperInfoFd_MultipleValidFds_001, TestSize.Level1)
{
    int32_t fd1 = CreateValidFd();
    ASSERT_GE(fd1, 0);
    int32_t fd2 = CreateValidFd();
    ASSERT_GE(fd2, 0);
    std::vector<WallpaperPictureInfo> infos;
    infos.push_back(MakeItem(FoldState::NORMAL, RotateState::PORT, fd1, TEST_LENGTH));
    infos.push_back(MakeItem(FoldState::UNFOLD_1, RotateState::LAND, fd2, TEST_LENGTH));
    WallpaperPictureInfoByParcel::CloseWallpaperInfoFd(infos);
    EXPECT_EQ(infos[0].fd, -1);
    EXPECT_EQ(infos[1].fd, -1);
    unlink(TMP_FILE_PATH);
}

} // namespace WallpaperMgrService
} // namespace OHOS
