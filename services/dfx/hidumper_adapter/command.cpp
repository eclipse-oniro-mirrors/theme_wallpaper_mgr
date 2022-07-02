#include "command.h"
namespace OHOS {
namespace MiscServices {
Command::Command(const std::vector<std::string> &argsFormat, const std::string &help, const Command::Action &action)
    : format_(argsFormat), help_(help), action_(action)
{
}

std::string Command::ShowHelp()
{
    return help_;
}

bool Command::DoAction(const std::vector<std::string> &input, std::string &output)
{
    return action_(input, output);
}

std::string Command::GetOption()
{
    return format_.at(0);
}

std::string Command::GetFormat()
{
    std::string formatStr;
    for (auto &seg : format_) {
        formatStr += seg;
        formatStr += " ";
    }
    return formatStr;
}
} // namespace MiscServices
} // namespace OHOS
