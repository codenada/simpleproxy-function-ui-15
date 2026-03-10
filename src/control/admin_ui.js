import { renderAdminPage } from "./ui.js";

function createAdminUiApi({ adminRoot }) {
  function handleAdminPage() {
    return renderAdminPage(adminRoot);
  }

  return {
    handleAdminPage,
  };
}

export { createAdminUiApi };
