<script lang="ts">
  export let item;

  import { parseISO, formatDistanceToNow } from "date-fns";

  let id = item.id || "";
  let issuer = item.issuer || "";
  let issuanceDate = item.issuanceDate || "";
  let issuanceDistanceToNow =
    issuanceDate !== ""
      ? formatDistanceToNow(parseISO(issuanceDate), {
          addSuffix: true,
        })
      : "";

  let subject = item.credentialSubject || null;

  let idText = id || "unavailable";
  let subjectText = subject?.id || "unavailable";
  let issuerText =
    issuer && issuanceDate
      ? issuer + " (" + issuanceDistanceToNow + ")"
      : "unavailable";
</script>

<p class="text-md">
  <span class="font-bold">{"ID: "}</span>
  <span class="text-xl">{idText}</span>
</p>
<p class="text-md">
  <span class="font-bold">{"Issuer: "}</span>
  <span class="text-xl" alt={issuerText}>{issuerText}</span>
</p>
<p class="text-md">
  <span class="font-bold">{"Subject: "}</span>
  <span class="text-xl">{subjectText}</span>
</p>
