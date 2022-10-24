const production = !process.env.ROLLUP_WATCH;

module.exports = {
  future: {
    purgeLayersByDefault: true,
    removeDeprecatedGapUtilities: true,
  },
  content: [
    "./src/**/*.svelte"
  ],
  theme: {
    extend: {},
  },
  variants: {
    extend: {},
  },
};
