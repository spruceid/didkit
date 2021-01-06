export const copyToClipboard = (data) => navigator.clipboard.writeText(data);

export const enumerateItems = (data) => {
  return data.map((item) => ({
    item,
    type:
      (Array.isArray(item?.type) && item?.type[0]) || item?.type || "Unknown",
    copy: () => copyToClipboard(JSON.stringify(item)),
  }));
};
