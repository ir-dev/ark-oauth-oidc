import { Window } from 'happy-dom';

/**
 * A real DOM (happy-dom) for the React and Vue adapter tests, installed as the globals those
 * libraries expect. The Ark client in these tests still gets its own FakeWindow, so the location
 * it reads and the navigations it makes stay under the test's control.
 */
export function installDom() {
  const dom = new Window({ url: 'http://127.0.0.1:5173/' });
  const names = ['window', 'document', 'HTMLElement', 'Element', 'Node', 'Text', 'MutationObserver', 'getComputedStyle', 'requestAnimationFrame', 'cancelAnimationFrame', 'SVGElement'];
  const previous = {};
  for (const name of names) {
    previous[name] = Object.getOwnPropertyDescriptor(globalThis, name);
    const value = name === 'window' ? dom : dom[name];
    Object.defineProperty(globalThis, name, { value: typeof value === 'function' && name !== 'window' && !/^[A-Z]/.test(name) ? value.bind(dom) : value, configurable: true, writable: true });
  }
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  return {
    dom,
    document: dom.document,
    container() {
      const div = dom.document.createElement('div');
      dom.document.body.appendChild(div);
      return div;
    },
    async uninstall() {
      for (const name of names) {
        if (previous[name]) Object.defineProperty(globalThis, name, previous[name]);
        else delete globalThis[name];
      }
      await dom.happyDOM.abort();
      dom.close();
    }
  };
}
