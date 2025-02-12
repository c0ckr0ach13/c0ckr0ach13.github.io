export function toc() {
  // if (document.querySelector('#core-wrapper h2,#core-wrapper h3')) {
    if (
      document.querySelector('#core-wrapper h1,#core-wrapper h2,#core-wrapper h3,#core-wrapper h4')
    ) {
    // see: https://github.com/tscanlin/tocbot#usage
    tocbot.init({
      tocSelector: '#toc',
      contentSelector: '.post-content',
      ignoreSelector: '[data-toc-skip]',
      // headingSelector: 'h2, h3',
      headingSelector: 'h1, h2, h3, h4',
      orderedList: false,
      scrollSmooth: false
    });
  }
}
