function prodPluginsIfProd() {
  const prod = !process.env.ROLLUP_WATCH;
  if (!prod) return [];
  const cssnanoOpts = {
    preset: ["default", { discardComments: { removeAll: true } }],
  };
  return [require("autoprefixer"), require("cssnano")(cssnanoOpts)];
}

module.exports = {
  plugins: [
    require("postcss-import"),
    require("tailwindcss"),
    ...prodPluginsIfProd(),
  ],
};
