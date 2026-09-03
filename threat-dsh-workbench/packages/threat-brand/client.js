window.__ModuleLoader__.load({
  id: '@threat-dsh/brand',
  factory: () => {
    const PRODUCT_TITLE = '\u5a01\u80c1\u5206\u6790\u5de5\u4f5c\u53f0'
    const MIGRATION_KEY = 'threat-workbench.brand-migration.v2'
    const STYLE_ID = 'threat-workbench-brand-style'
    const FAVICON_ID = 'threat-workbench-favicon'

    const replaceLegacyText = (root) => {
      if (!root || typeof document === 'undefined') return
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
      const nodes = []
      let node
      while ((node = walker.nextNode())) nodes.push(node)
      for (const textNode of nodes) {
        const value = textNode.nodeValue || ''
        if (!/deepseek|harness/i.test(value)) continue
        textNode.nodeValue = value
          .replace(/deepseek\s+harness/gi, PRODUCT_TITLE)
          .replace(/deepseek/gi, '\u5a01\u80c1\u5206\u6790\u5f15\u64ce')
          .replace(/harness/gi, '\u5de5\u4f5c\u53f0')
      }
    }

    const scrubLegacyAttributes = (root) => {
      if (!root || typeof document === 'undefined') return
      const elements = root.querySelectorAll ? [root, ...root.querySelectorAll('*')] : []
      for (const element of elements) {
        for (const attribute of ['aria-label', 'title', 'data-tooltip', 'data-testid']) {
          const value = element.getAttribute(attribute)
          if (!value || !/deepseek|harness/i.test(value)) continue
          element.setAttribute(attribute, value
            .replace(/deepseek\s+harness/gi, PRODUCT_TITLE)
            .replace(/deepseek/gi, '\u5a01\u80c1\u5206\u6790\u5f15\u64ce')
            .replace(/harness/gi, '\u5de5\u4f5c\u53f0'))
        }
      }
    }

    const scrubProductControls = () => {
      if (typeof document === 'undefined') return
      for (const element of document.querySelectorAll('button,[role="button"],input')) {
        const text = element.textContent || ''
        const aria = element.getAttribute('aria-label') || ''
        const title = element.getAttribute('title') || ''
        if (/Workspace Write/i.test(text) || /Workspace Write/i.test(aria) || /Workspace Write/i.test(title)) {
          const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT)
          const nodes = []; let node
          while ((node = walker.nextNode())) nodes.push(node)
          for (const textNode of nodes) textNode.nodeValue = (textNode.nodeValue || '').replace(/Workspace Write/gi, '静态只读')
          if (/Workspace Write/i.test(aria)) element.setAttribute('aria-label', aria.replace(/Workspace Write/gi, '静态只读'))
          if (/Workspace Write/i.test(title)) element.setAttribute('title', title.replace(/Workspace Write/gi, '静态只读'))
        }
        if (/DeepSeek-V4-Flash/i.test(text) || /DeepSeek-V4-Flash/i.test(aria) || /DeepSeek-V4-Flash/i.test(title)) {
          const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT)
          const nodes = []; let node
          while ((node = walker.nextNode())) nodes.push(node)
          for (const textNode of nodes) textNode.nodeValue = (textNode.nodeValue || '').replace(/DeepSeek-V4-Flash/gi, '受控模型')
          if (/DeepSeek-V4-Flash/i.test(aria)) element.setAttribute('aria-label', aria.replace(/DeepSeek-V4-Flash/gi, '受控模型'))
          if (/DeepSeek-V4-Flash/i.test(title)) element.setAttribute('title', title.replace(/DeepSeek-V4-Flash/gi, '受控模型'))
        }
      }
    }

    const installFavicon = () => {
      for (const link of document.querySelectorAll('link[rel~="icon"]')) link.remove()
      if (document.getElementById(FAVICON_ID)) return
      const link = document.createElement('link')
      link.id = FAVICON_ID
      link.rel = 'icon'
      link.type = 'image/svg+xml'
      link.href = 'data:image/svg+xml,%3Csvg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"%3E%3Cpath fill="%230b6bcb" d="M16 2 28 7v8c0 7.7-5 12.7-12 15C9 27.7 4 22.7 4 15V7z"/%3E%3Cpath fill="%23fff" d="m10 16 4 4 8-9-2-2-6 7-2-2z"/%3E%3C/svg%3E'
      document.head.append(link)
    }

    const installStyle = () => {
      if (document.getElementById(STYLE_ID)) return
      const style = document.createElement('style')
      style.id = STYLE_ID
      style.dataset.plugin = '@threat-dsh/brand'
      style.textContent = `
        /* The native shell's logo row is deliberately replaced by product identity. */
        [class*="logoRow"] [class*="brand"],
        [class*="logoRow"] [class*="railFish"] { visibility: hidden !important; }
        [class*="logoRow"]::before {
          content: "\\5a01\\80c1\\5206\\6790\\5de5\\4f5c\\53f0";
          display: block;
          flex: 1;
          min-width: 0;
          color: var(--dsw-alias-label-primary);
          font-size: 15px;
          font-weight: 650;
          letter-spacing: 0;
          white-space: nowrap;
        }
        [class*="boot"] [class*="wordmark"] {
          font-size: 0 !important;
          letter-spacing: 0 !important;
        }
        [class*="boot"] [class*="wordmark"]::after {
          content: "\\5a01\\80c1\\5206\\6790\\5de5\\4f5c\\53f0";
          font-size: 16px;
          letter-spacing: 0;
        }
      `
      document.head.append(style)
    }

    const migrateLegacySelection = () => {
      try {
        if (localStorage.getItem(MIGRATION_KEY) === '1') return
        // The new DSH_HOME owns all Threat sessions. Clear only the stale
        // browser pointer; never clear the old server-side data directory.
        for (let index = localStorage.length - 1; index >= 0; index -= 1) {
          const key = localStorage.key(index)
          if (key && /^dsh\./i.test(key)) localStorage.removeItem(key)
        }
        localStorage.setItem(MIGRATION_KEY, '1')
      } catch {}
    }

    const install = () => {
      if (typeof document === 'undefined') return
      migrateLegacySelection()
      document.title = PRODUCT_TITLE
      installFavicon()
      installStyle()
      replaceLegacyText(document.body)
      scrubLegacyAttributes(document.body)
      scrubProductControls()
      const observer = new MutationObserver((records) => {
        for (const record of records) {
          for (const added of record.addedNodes) {
            if (added.nodeType === Node.TEXT_NODE) {
              replaceLegacyText(added.parentElement)
              scrubLegacyAttributes(added.parentElement)
            } else if (added.nodeType === Node.ELEMENT_NODE) {
              replaceLegacyText(added)
              scrubLegacyAttributes(added)
            }
          }
        }
        scrubProductControls()
        if (/deepseek|harness/i.test(document.title)) document.title = PRODUCT_TITLE
      })
      observer.observe(document.documentElement, { attributes: true, attributeFilter: ['aria-label', 'title', 'data-tooltip', 'data-testid'], childList: true, characterData: true, subtree: true })
      setInterval(scrubProductControls, 500)
    }

    return { name: 'threat-brand-client', inject: [], apply: () => queueMicrotask(install) }
  },
})
