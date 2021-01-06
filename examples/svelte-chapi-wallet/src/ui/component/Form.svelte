<div class="container mx-auto shadow my-8 px-3 py-4 rounded">
  <h1 class="text-xl text-black">
    <slot name="title" />
  </h1>
  <h2 class="text-md text-gray-500">
    <slot name="subtitle" />
  </h2>
  <form class="text-center mt-8" on:submit|preventDefault>
    <slot />
  </form>
</div>
