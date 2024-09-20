import { viteBundler } from '@vuepress/bundler-vite'
import { defineUserConfig } from 'vuepress'
import { defaultTheme } from '@vuepress/theme-default'

export default defineUserConfig({
  bundler: viteBundler(),
  lang: 'en-US',
  title: 'Golang YSF Reflector',
  description: 'Documentation for the Golang implementation of a YSF Reflector',
  base: '/goYSFReflector/',  // GitHub Pages repo base
  theme: defaultTheme({
    navbar: [
      {
        text: 'Getting Started',
        link: '/gettingstarted/gettingstarted.md'
      }
    ],
    sidebar: [
      {
        text: 'Getting Started',
        link: '/gettingstarted/gettingstarted.md'
      },
      {
        text: 'YSF Protocol',
        link: '/protocol/protocol.md'
      }
    ],
    sidebarDepth: 2, // Adjusts the depth of headers in the sidebar
  }),
})
