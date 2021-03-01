const path = require("path");

module.exports = {
  entry: {
    "didkit-loader": "./didkit-loader.js",
  },
  devtool: "source-map",
  optimization: {
    minimize: true,
  },
  output: {
    path: path.resolve(__dirname),
    filename: "[name].min.js",
    library: "DIDKitLoader",
    libraryTarget: "umd",
  },
};
