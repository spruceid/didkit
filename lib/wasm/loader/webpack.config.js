const path = require("path");

module.exports = {
  entry: {
    "didkit-loader": "./didkit-loader.js",
  },
  devtool: "source-map",
  optimization: {
    minimize: true,
  },
  module: {
    rules: [
      {
        test: /\.wasm$/,
        use: [{ loader: "wasm-loader" }],
      },
    ],
  },
  output: {
    path: path.resolve(__dirname),
    filename: "[name].min.js",
    library: "DIDKitLoader",
    libraryTarget: "umd",
  },
};
