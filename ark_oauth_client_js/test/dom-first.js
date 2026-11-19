import { installDom } from './dom.js';

/**
 * Imported first by tests whose framework reads `document` when its own module loads (Vue's
 * runtime-dom does), so the DOM already exists by then. ES modules evaluate in import order.
 */
export const dom = installDom();
