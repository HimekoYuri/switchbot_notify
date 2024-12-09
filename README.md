# switchbot_notify

this is a switch bot event to notify discord.

# requirements

- AWS Lambda
- AWS Lambda HTTP Stream
- discord server WEB Hook URL
- Switch bot API key

# definition

- Switchbot API をゲットしてWebHookにする
  - AWS Lambdaで実行する。
- 以下をWebHookでdiscordへ通知する
  - 定時刻でLambdaを起動してSwitchbotで計測してる室温/湿度を通知する
  - 鍵の状態が変更される事に通知する

# reference

[Zenn 7oh](https://zenn.dev/7oh/scraps/c540b175727f28)様

[Qiita narikakun](https://qiita.com/narikakun/items/4868c0bef27)様

[Zenn Tanny](https://zenn.dev/tanny/articles/e03e28d1bbd37b)様

[yamamanx](https://www.yamamanx.com/lambda-function-update-environment/)様

# Use this program manual

Please check this [blog site page](https://kohaku-kageroh.hatenablog.com/entry/20241209/1733746235).
