const path = require("path");

module.exports = {
  mode: 'production',
  entry: {
    "didkit-asm": "./didkit-output.js",
  },
  optimization: {
    minimize: true,
  },
  output: {
    path: path.resolve(__dirname),
    filename: "[name].min.js",
    library: 'DIDKit',
  },
};
