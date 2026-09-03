window.__ModuleLoader__.load({
  id: '@threat-dsh/plugin-acceptance-example',
  factory: (require) => {
    const module = { exports: {} }
    const React = require('react')
    const View = () => React.createElement('section', { 'data-threat-view': 'plugin-test' }, 'Plugin Test: dynamically loaded view')
    module.exports.name = 'threat-plugin-acceptance-example-client'
    module.exports.inject = ['slots']
    module.exports.apply = (ctx) => ctx.slots.inject('conversation.view', () => ctx.slots.register({ name: 'conversation.view', id: 'plugin-test', order: 999, label: 'Plugin Test' }, View))
    return module.exports
  },
})
