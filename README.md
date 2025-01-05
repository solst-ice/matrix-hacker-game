# Matrix Hacker Game

A clicker/idle game with a cybersecurity theme, where you hack the Matrix by clicking anywhere or pressing any key. Unlock increasingly powerful hacks as you progress through ranks from Script Kiddie to AI 0day.

## Features

- Click or press any key to hack
- Multiple progression mechanics:
  - Critical hits (red)
  - Legendary hits (orange)
  - 0day exploits (pink)
  - Double clicks
  - Automatic hacks per second
- 6 ranks to progress through:
  1. Script Kiddie
  2. Malware Developer
  3. C2 Operator
  4. State-sponsored Actor
  5. APT
  6. AI 0day
- Matrix-style falling character animation
- Visual effects for critical hits, explosions, and special events

## Tech Stack

- React (Hooks)
- CSS Animations
- No external dependencies

## Game Mechanics

- Start by clicking/pressing keys to gain points
- Unlock the HACK button at 50 points
- Buy upgrades to increase your hacking power
- Progress through ranks by purchasing upgrades
- Watch for special 0day opportunities that fall down the screen
- Reach the final rank to unlock the mysterious GLITCH...

## Development

```bash
# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build

# Deploy to GitHub Pages
npm run deploy
```

## Deployment

This game is deployed using GitHub Pages. To deploy your own instance:

1. Update `homepage` in package.json with your GitHub Pages URL
2. Update `base` in vite.config.js with your repository name
3. Run `npm run deploy`
4. Enable GitHub Pages in your repository settings

## Testing

Use this to set the score, for easier testing.

```bash
// Find the React fiber and set score directly
const scoreElement = document.querySelector('.score');
const fiberKey = Object.keys(scoreElement).find(key => key.startsWith('__reactFiber$'));
if (fiberKey) {
    const fiber = scoreElement[fiberKey];
    let current = fiber;
    while (current) {
        if (current.memoizedState?.queue?.dispatch) {
            // Explicitly set to a number
            current.memoizedState.queue.dispatch(100000000000);
            break;
        }
        current = current.return;
    }
}
```

## License

MIT
