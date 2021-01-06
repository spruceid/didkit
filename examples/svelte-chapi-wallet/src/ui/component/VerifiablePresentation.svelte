<script lang="ts">
  export let item;

  import { parseISO, formatDistanceToNow } from "date-fns";

  let isArray = Array.isArray(item.verifiableCredential);
  let isMultiple = isArray && item.verifiableCredential.length > 1;
  let vc = !isMultiple
    ? isArray
      ? item.verifiableCredential[0]
      : item.verifiableCredential
    : null;
  let id = vc.id || "";
  let issuer = vc.issuer || "";
  let issuanceDate = vc.issuanceDate || "";
  let issuanceDistanceToNow =
    issuanceDate !== ""
      ? formatDistanceToNow(parseISO(issuanceDate), {
          addSuffix: true,
        })
      : "";

  let subject = vc.credentialSubject || null;

  let idText = id || "unavailable";
  let subjectText = subject?.id || "unavailable";
  let issuerText =
    issuer && issuanceDate
      ? issuer + " (" + issuanceDistanceToNow + ")"
      : "unavailable";
</script>

{#if isArray}
  <p class="text-md">
    <span class="font-bold">
      {"VP with multiple credentials, preview is unavailable"}
    </span>
  </p>
{:else}
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
{/if}
