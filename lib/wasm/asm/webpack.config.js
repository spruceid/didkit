const path = require("path");

module.exports = {
  entry: {
    "asm-loader": "./asm-loader.js",
  },
  devtool: "source-map",
  optimization: {
    minimize: true,
  },
  output: {
    path: path.resolve(__dirname),
    filename: "[name].min.js",
    library: "DIDKitASMLoader",
    libraryTarget: "umd",
  },
};
