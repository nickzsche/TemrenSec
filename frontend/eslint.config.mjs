import coreWebVitals from 'eslint-config-next/core-web-vitals'

// Flat ESLint config for Next.js 16 (next lint was removed). Uses the
// core-web-vitals preset. react-hooks/set-state-in-effect (new in Next 16) is
// downgraded to a warning: setting state in an effect is idiomatic here for
// hydration guards and post-fetch data loading.
export default [
  { ignores: ['.next/**', 'node_modules/**', 'next-env.d.ts'] },
  ...coreWebVitals,
  {
    rules: {
      'react-hooks/set-state-in-effect': 'warn',
    },
  },
]
