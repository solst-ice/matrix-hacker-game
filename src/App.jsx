import { useState, useEffect, useRef } from 'react'
import './MatrixRain.css'

function App() {
  const [score, setScore] = useState(0)
  const [matrixChars, setMatrixChars] = useState([])
  const [showHackButton, setShowHackButton] = useState(false)
  const [showHackOverlay, setShowHackOverlay] = useState(false)
  const [ownedHacks, setOwnedHacks] = useState({
    nmapScanner: 0,
    httpProxy: 0,
    aslrBypass: 0,
    metasploit: 0,
    idaPro: 0,
    doubleRot13: 0,
    unauthRce: 0,
    nopSled: 0,
    steganography: 0,
    exfiltrateSSN: 0,
    eternalBlue: 0,
    chromeBackdoor: 0,
    stuxnet: 0,
    xssPopup: 0,
    bgpHijack: 0,
    phishClownflare: 0,
    aflFuzz: 0,
    unpropDNS: 0,
    spfHardfail: 0,
    lgtmPR: 0,
    downloadRam: 0,
    flipperZero: 0,
    rowHammer: 0,
    glitch: 0,
    banCpp: 0,
    enableMfa: 0,
    ascend: 0
  })
  const [multipliers, setMultipliers] = useState({
    criticalChance: 1,
    trailLength: 0.2,
    doubleClickChance: 0,
    critMultiplier: 10,
    hacksPerSecond: 0,
    baseZerodayChance: 5,
    zerodayChance: 0,
    zerodayBonus: 0,
    legendaryChance: 0,
    legendaryMultiplier: 100,
    basePoints: 1
  })
  const [zerodays, setZerodays] = useState([])
  const MAX_MATRIX_CHARS = 800
  const [previousRank, setPreviousRank] = useState(null)
  const [isTransitioning, setIsTransitioning] = useState(false)
  const [hiddenHacks, setHiddenHacks] = useState([])
  const [isUIDisabled, setIsUIDisabled] = useState(false)
  const [isGlitchMode] = useState(() => {
    const glitchLevel = parseInt(localStorage.getItem('glitchLevel') || '0')
    return glitchLevel > 0 && localStorage.getItem('glitchMode') === 'true'
  })
  const [hasClickedHackButton, setHasClickedHackButton] = useState(false)
  const [counted0days, setCounted0days] = useState(new Set())
  const idCounterRef = useRef(0)

  const zalgo = (text) => {
    const zalgoChars = [
      '\u0300', '\u0301', '\u0302', '\u0303', '\u0304', '\u0305', '\u0306', '\u0307',
      '\u0308', '\u0309', '\u030A', '\u030B', '\u030C', '\u030D', '\u030E', '\u030F'
    ]
    return text.split('').map(char => 
      char + zalgoChars.map(() => 
        zalgoChars[Math.floor(Math.random() * zalgoChars.length)]
      ).join('')
    ).join('')
  }

  // Helper function for colored text
  const colorText = {
    legendary: (text) => <span style={{ color: '#ffa500' }}>{text}</span>,
    critical: (text) => <span style={{ color: '#ff0000' }}>{text}</span>,
    zeroday: (text) => <span style={{ color: '#ff69b4' }}>{text}</span>
  }

  const RANK_HACKS = {
    'Script Kiddie': {
      nmapScanner: {
        name: "Nmap Scanner",
        baseCost: 8,
        maxLevel: 5,
        description: <>Increases {colorText.critical('critical')} chance by <span className="stat-increase">+1.25%</span></>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            criticalChance: prev.criticalChance + 1.25
          }))
        }
      },
      httpProxy: {
        name: "HTTP Proxy",
        baseCost: 16,
        maxLevel: 5,
        description: <>Adds <span className="stat-increase">+0.5%</span> chance for double clicks</>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            doubleClickChance: prev.doubleClickChance + 0.5
          }))
        }
      },
      aslrBypass: {
        name: "ASLR Bypass",
        baseCost: 16,
        maxLevel: 5,
        description: <>Increases {colorText.critical('critical')} multiplier by <span className="stat-increase">+2x</span></>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            critMultiplier: prev.critMultiplier + 2
          }))
        }
      },
      metasploit: {
        name: "Metasploit",
        baseCost: 32,
        maxLevel: 5,
        description: <>Automatically triggers <span className="stat-increase">+1</span> hack per second</>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            hacksPerSecond: prev.hacksPerSecond + 1
          }))
        }
      }
    },
    'Malware Developer': {
      idaPro: {
        name: "IDA Pro License",
        baseCost: 64,
        maxLevel: 5,
        description: <>Increases {colorText.critical('critical')} chance by <span className="stat-increase">+1.75%</span></>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            criticalChance: prev.criticalChance + 1.75
          }))
        }
      },
      doubleRot13: {
        name: "Double-ROT13 Encryption",
        baseCost: 64,
        maxLevel: 5,
        description: <>Make each click worth <span className="stat-increase">+1</span> point</>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            basePoints: (prev.basePoints || 1) + 1
          }))
        }
      },
      unauthRce: {
        name: "Unauth RCE",
        baseCost: 256,
        maxLevel: 5,
        description: <>Adds <span className="stat-increase">+1%</span> chance for {colorText.legendary('LEGENDARY')} hits (100x)</>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            legendaryChance: (prev.legendaryChance || 0) + 0.01
          }))
        }
      },
      nopSled: {
        name: "NOP Sled",
        baseCost: 64,
        maxLevel: 5,
        description: <>Adds <span className="stat-increase">+1%</span> chance to trigger a {colorText.zeroday('0day')}</>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            zerodayChance: (prev.zerodayChance || 0) + 1
          }))
        }
      }
    },
    'C2 Operator': {
      steganography: {
        name: "Steganography C2 Comms",
        baseCost: 1024,
        maxLevel: 5,
        description: <>Increases {colorText.critical('critical')} chance by <span className="stat-increase">+1%</span> and multiplier by <span className="stat-increase">+2x</span></>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            criticalChance: prev.criticalChance + 1,
            critMultiplier: prev.critMultiplier + 2
          }))
        }
      },
      exfiltrateSSN: {
        name: "Exfiltrate all SSNs",
        baseCost: 256,
        maxLevel: 5,
        description: <>Adds <span className="stat-increase">+1.5%</span> chance for double clicks</>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            doubleClickChance: prev.doubleClickChance + 1.5
          }))
        }
      },
      eternalBlue: {
        name: "EternalBlue - MS17-010",
        baseCost: 2048,
        maxLevel: 5,
        description: <>Adds <span className="stat-increase">+1</span> hack per second</>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            hacksPerSecond: prev.hacksPerSecond + 1
          }))
        }
      },
      chromeBackdoor: {
        name: "Backdoor Chrome Extension",
        baseCost: 4096,
        maxLevel: 5,
        description: <>Adds <span className="stat-increase">+1%</span> {colorText.legendary('legendary')} chance and increases {colorText.legendary('legendary')} multiplier by <span className="stat-increase">+5x</span></>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            legendaryChance: (prev.legendaryChance || 0) + 0.01,
            legendaryMultiplier: (prev.legendaryMultiplier || 100) + 5
          }))
        }
      }
    },
    'State-sponsored Actor': {
      stuxnet: {
        name: "Stuxnet on a USB",
        baseCost: 2048,
        maxLevel: 5,
        description: <>Increases {colorText.critical('critical')} chance by <span className="stat-increase">+2.8%</span> and multiplier by <span className="stat-increase">+2x</span></>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            criticalChance: prev.criticalChance + 2.8,
            critMultiplier: prev.critMultiplier + 2
          }))
        }
      },
      xssPopup: {
        name: "XSS Alert(1); Pop-up",
        baseCost: 4096,
        maxLevel: 5,
        description: <>Adds <span className="stat-increase">+3,000</span> points to {colorText.zeroday('0day')} rewards</>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            zerodayBonus: (prev.zerodayBonus || 0) + 3000
          }))
        }
      },
      bgpHijack: {
        name: "Hijack BGP",
        baseCost: 8192,
        maxLevel: 5,
        description: <>Adds <span className="stat-increase">+2</span> hacks per second</>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            hacksPerSecond: prev.hacksPerSecond + 2
          }))
        }
      },
      phishClownflare: {
        name: "Phish Clownflare Employee",
        baseCost: 16384,
        maxLevel: 5,
        description: <>Adds <span className="stat-increase">+1%</span> {colorText.legendary('legendary')} chance and <span className="stat-increase">+10x</span> {colorText.legendary('legendary')} multiplier</>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            legendaryChance: (prev.legendaryChance || 0) + 0.01,
            legendaryMultiplier: (prev.legendaryMultiplier || 100) + 10
          }))
        }
      }
    },
    'APT': {
      aflFuzz: {
        name: "Fuzz with AFL++",
        baseCost: 32768,
        maxLevel: 5,
        description: <>Increases {colorText.critical('critical')} chance by <span className="stat-increase">+3%</span></>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            criticalChance: prev.criticalChance + 3
          }))
        }
      },
      unpropDNS: {
        name: "Unpropagate DNS",
        baseCost: 16384,
        maxLevel: 5,
        description: <>Increases double click chance by <span className="stat-increase">+3%</span></>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            doubleClickChance: prev.doubleClickChance + 3
          }))
        }
      },
      spfHardfail: {
        name: "Set SPF to Hardfail",
        baseCost: 16384,
        maxLevel: 5,
        description: <>Increases {colorText.critical('critical')} and {colorText.legendary('legendary')} multipliers by <span className="stat-increase">+3x</span> each</>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            critMultiplier: prev.critMultiplier + 3,
            legendaryMultiplier: (prev.legendaryMultiplier || 100) + 3
          }))
        }
      },
      lgtmPR: {
        name: "LGTM a GitHub PR",
        baseCost: 32768,
        maxLevel: 5,
        description: <>Increases hacks per second by <span className="stat-increase">+2</span></>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            hacksPerSecond: prev.hacksPerSecond + 2
          }))
        }
      }
    },
    'AI 0day': {
      downloadRam: {
        name: "Download more RAM",
        baseCost: 65536,
        maxLevel: 5,
        description: <>Increases {colorText.zeroday('0day')} chance by <span className="stat-increase">+4%</span> and reward by <span className="stat-increase">+5,000</span> points</>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            zerodayChance: (prev.zerodayChance || 0) + 4,
            zerodayBonus: (prev.zerodayBonus || 0) + 5000
          }))
        }
      },
      flipperZero: {
        name: "Overclock Flipper Zero",
        baseCost: 131072,
        maxLevel: 5,
        description: <>Increases {colorText.zeroday('0day')} reward by <span className="stat-increase">+191,800</span> points</>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            zerodayBonus: (prev.zerodayBonus || 0) + 191800
          }))
        }
      },
      rowHammer: {
        name: "ROWHAMMER",
        baseCost: 524288,
        maxLevel: 5,
        description: <>Increases {colorText.critical('critical')} multiplier by <span className="stat-increase">+60x</span> and {colorText.legendary('legendary')} multiplier by <span className="stat-increase">+100x</span></>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            critMultiplier: prev.critMultiplier + 60,
            legendaryMultiplier: (prev.legendaryMultiplier || 100) + 100
          }))
        }
      },
      glitch: {
        name: zalgo("GLITCH"),
        baseCost: 2097152,
        maxLevel: 20,
        description: <span style={{ color: '#800080' }}>{ 
          ownedHacks.glitch === 0 ? 
          zalgo("????????????????") : 
          zalgo("ASCEND TO THE NEXT GLITCH LEVEL") 
        }</span>,
        onBuy: () => {
          // Increment glitch level with each purchase
          setOwnedHacks(prev => {
            const newLevel = prev.glitch + 1
            localStorage.setItem('glitchLevel', newLevel.toString())
            return {
              ...prev,
              glitch: newLevel
            }
          })

          // Disable UI immediately
          setIsUIDisabled(true)
          localStorage.setItem('glitchMode', 'true')

          // Add a small delay before starting the glitch animation
          setTimeout(() => {
            const width = window.innerWidth
            const height = window.innerHeight
            const totalChars = 1500
            const batchSize = 100
            const batches = Math.ceil(totalChars / batchSize)
            let currentBatch = 0

            const addBatch = () => {
              if (currentBatch >= batches) {
                setTimeout(() => {
                  const flash = document.createElement('div')
                  flash.style.position = 'fixed'
                  flash.style.top = '0'
                  flash.style.left = '0'
                  flash.style.width = '100%'
                  flash.style.height = '100%'
                  flash.style.background = 'white'
                  flash.style.zIndex = '9999'
                  flash.style.animation = 'flash 1s ease-out forwards'
                  document.body.appendChild(flash)

                  // Reload immediately when animation ends
                  flash.addEventListener('animationend', () => {
                    window.location.reload()
                  })
                }, 1000)
                return
              }

              const chars = new Array(batchSize).fill(null).map((_, i) => ({
                char: matrixCharacters[Math.floor(Math.random() * matrixCharacters.length)],
                x: Math.random() * width,
                y: Math.random() * height,
                id: Date.now() + currentBatch * batchSize + i,
                opacity: 1,
                startTime: Date.now(),
                duration: 2000,
                style: {
                  color: `hsl(${Math.random() * 360}, 100%, 50%)`,
                  fontSize: '24px',
                  textShadow: '0 0 5px currentColor'
                }
              }))

              setMatrixChars(prev => [...prev.slice(-MAX_MATRIX_CHARS + batchSize), ...chars])
              currentBatch++
              requestAnimationFrame(addBatch)
            }

            requestAnimationFrame(addBatch)
          }, 100) // Add 100ms delay
        }
      },
      banCpp: {
        name: zalgo("BAN C++"),
        baseCost: 2097152,
        maxLevel: 5,
        description: <>Adds <span className="stat-increase">+4%</span> {colorText.legendary('legendary')} chance, increases {colorText.legendary('legendary')} multiplier by <span className="stat-increase">+100x</span>, and adds <span className="stat-increase">+9,800,000</span> to {colorText.zeroday('0day')} rewards</>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            legendaryChance: (prev.legendaryChance || 0) + 0.04,
            legendaryMultiplier: (prev.legendaryMultiplier || 100) + 100,
            zerodayBonus: (prev.zerodayBonus || 0) + 9800000
          }))
        }
      },
      enableMfa: {
        name: zalgo("Enable MFA"),
        baseCost: 4194304,
        maxLevel: 5,
        description: <>Adds <span className="stat-increase">+13%</span> {colorText.legendary('legendary')} chance, increases {colorText.critical('critical')} and {colorText.legendary('legendary')} multipliers by <span className="stat-increase">+100x</span>, adds <span className="stat-increase">+14%</span> {colorText.zeroday('0day')} chance and <span className="stat-increase">+50,000,000</span> to {colorText.zeroday('0day')} rewards</>,
        onBuy: () => {
          setMultipliers(prev => ({
            ...prev,
            legendaryChance: (prev.legendaryChance || 0) + 0.13,
            critMultiplier: prev.critMultiplier + 100,
            legendaryMultiplier: (prev.legendaryMultiplier || 100) + 100,
            zerodayChance: (prev.zerodayChance || 0) + 14,
            zerodayBonus: (prev.zerodayBonus || 0) + 50000000
          }))
        }
      },
      ascend: {
        name: "Ascend into Singularity",
        baseCost: 1,
        maxLevel: 1,
        description: <>Ask the final question.</>,
        onBuy: () => {
          // Disable all UI interaction
          setIsUIDisabled(true)
          
          // Clear all intervals to stop effects
          const highestId = window.setTimeout(() => {}, 0)
          for (let i = 0; i <= highestId; i++) {
            window.clearTimeout(i)
            window.clearInterval(i)
          }
          
          // Remove all column flash elements
          const flashes = document.querySelectorAll('.column-flash')
          flashes.forEach(flash => flash.remove())
          
          // Fade out all UI elements immediately
          const gameContainer = document.querySelector('.game-container')
          const matrixBackground = document.querySelector('.matrix-background')
          const hackOverlay = document.querySelector('.hack-overlay')
          
          if (gameContainer) gameContainer.style.animation = 'fadeOut 2s forwards'
          if (hackOverlay) hackOverlay.style.animation = 'fadeOut 2s forwards'
          if (matrixBackground) matrixBackground.style.animation = 'fadeOut 2s forwards'
          
          // Start the white fade after UI elements are gone
          setTimeout(() => {
            document.body.style.animation = 'ascendToWhite 5s forwards'
            
            // Clear all game state
            setShowHackButton(false)
            setShowHackOverlay(false)
            setMatrixChars([])
            
            // Add the final message
            setTimeout(() => {
              const message = document.createElement('div')
              message.style.cssText = `
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                font-family: 'Times New Roman', serif;
                font-size: 24px;
                color: #000;
                text-align: center;
                opacity: 0;
                animation: fadeInMessage 2s forwards;
              `
              message.textContent = 'You have ascended. Let there be light.'
              document.body.appendChild(message)
            }, 3000)
          }, 2000)
        }
      }
    }
  }

  const matrixCharacters = 'ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍ012345789Z'

  const getTrailLength = () => {
    const ranks = ['Script Kiddie', 'Malware Developer', 'C2 Operator', 'State-sponsored Actor', 'APT', 'AI 0day']
    const currentRank = getRank().name
    const rankIndex = ranks.indexOf(currentRank)
    return rankIndex + 1  // Trail length starts at 1 for Script Kiddie and increases by 1 per rank
  }

  const getCriticalChance = () => 0.01 * multipliers.criticalChance
  const getDoubleClickChance = () => 0.01 * multipliers.doubleClickChance
  const getCritMultiplier = () => {
    return multipliers.critMultiplier || 10
  }

  const getLegendaryMultiplier = () => {
    return multipliers.legendaryMultiplier || 100
  }

  const addMatrixCharacter = (clickX = null, isLegendary = false, isCritical = false) => {
    const x = clickX ? 
      clickX - 100 + (Math.random() * 200) : 
      Math.random() * window.innerWidth
    
    // Use ref for counter to ensure uniqueness
    const baseId = `${Date.now()}-${idCounterRef.current++}`
    
    // Calculate time needed for each character to reach past bottom
    const windowHeight = window.innerHeight
    const extraDistance = windowHeight * 0.2 // 20% extra distance
    const fallSpeed = windowHeight / 2 // pixels per second
    
    // Get trail length based on rank - same for all interaction types
    const trailLength = getTrailLength()
    
    // Create trail of characters
    const trail = Array.from({ length: trailLength }, (_, index) => ({
      char: matrixCharacters[Math.floor(Math.random() * matrixCharacters.length)],
      x,
      y: -20 - (index * 20),
      id: `${baseId}-${index}-${Math.random()}`,  // Add extra randomness
      opacity: 1 - (index * 0.2),
      isCritical,
      isLegendary,
      startTime: Date.now(),
      duration: (windowHeight + extraDistance + 20 + (index * 20)) / fallSpeed * 1000
    }))

    setMatrixChars(prev => {
      const now = Date.now()
      return [
        ...prev
          .filter(char => now - char.startTime < char.duration)
          .slice(-MAX_MATRIX_CHARS + trail.length),
        ...trail
      ]
    })

    return isCritical || isLegendary
  }

  const handleInteraction = (event) => {
    // Capture current values to ensure consistency
    const currentDoubleChance = getDoubleClickChance()
    const clickX = event?.clientX ?? Math.random() * window.innerWidth
    
    // Function to process a single interaction - same for all types
    const processInteraction = () => {
      let points = multipliers.basePoints || 1

      // Check for legendary first (if available)
      if (multipliers.legendaryChance && Math.random() < multipliers.legendaryChance) {
        addMatrixCharacter(clickX, true) // true = isLegendary
        points *= getLegendaryMultiplier() // Apply legendary multiplier
      }
      
      // Then check for critical - this should still apply even on legendary hits
      const isCritical = Math.random() < getCriticalChance()
      if (isCritical) {
        points *= getCritMultiplier() // Apply critical multiplier
        addMatrixCharacter(clickX, false, isCritical)
      } else if (!multipliers.legendaryChance || Math.random() >= multipliers.legendaryChance) {
        // Only add normal character if not legendary or critical
        addMatrixCharacter(clickX, false, false)
      }
      
      return points
    }

    // Always do at least one interaction
    let totalPoints = processInteraction()
    
    // Check for double click - applies to both manual and auto
    if (currentDoubleChance >= 1 || Math.random() <= currentDoubleChance) {
      totalPoints += processInteraction()
    }

    setScore(prev => Math.min(prev + totalPoints, Number.MAX_SAFE_INTEGER))
  }

  const handleHack = () => {
    setHasClickedHackButton(true)
    setShowHackOverlay(true)
  }

  const getHackCost = (hackId) => {
    // Find the hack in any rank group
    let hack = null
    for (const rankHacks of Object.values(RANK_HACKS)) {
      if (rankHacks[hackId]) {
        hack = rankHacks[hackId]
        break
      }
    }

    if (!hack) return 0

    const level = ownedHacks[hackId] || 0
    const multiplier = Math.pow(2, level)
    return Math.floor(hack.baseCost * multiplier)
  }

  const handleBuyHack = (hackId) => {
    // Find the hack in any rank group
    let hack = null
    for (const rankHacks of Object.values(RANK_HACKS)) {
      if (rankHacks[hackId]) {
        hack = rankHacks[hackId]
        break
      }
    }

    if (!hack) return

    const currentLevel = ownedHacks[hackId]
    const cost = getHackCost(hackId)

    if (score >= cost && currentLevel < hack.maxLevel) {
      setScore(prev => prev - cost)
      setOwnedHacks(prev => ({
        ...prev,
        [hackId]: prev[hackId] + 1
      }))
      hack.onBuy()

      // If this purchase maxes out the hack, start fade out
      if (currentLevel + 1 >= hack.maxLevel) {
        setTimeout(() => {
          setHiddenHacks(prev => [...prev, hackId])
        }, 2000) // Remove from DOM after animation completes
      }
    }
  }

  const addZeroday = () => {
    const windowWidth = window.innerWidth
    const safeWidth = windowWidth - (5 * 20) // 5 columns, assuming each is ~20px wide
    
    // Restrict x position to safe area
    const x = Math.random() * safeWidth
    
    const baseId = Date.now() + Math.random()
    const windowHeight = window.innerHeight
    const extraDistance = windowHeight * 0
    const fallSpeed = windowHeight / 4

    const opacityStep = 0.8 / 15

    const trail = Array.from({ length: 15 }, (_, index) => ({
      char: matrixCharacters[Math.floor(Math.random() * matrixCharacters.length)],
      x,
      y: -20 - (index * 20),
      id: baseId + index,
      opacity: 1 - (opacityStep * index),
      isZeroday: true,
      startTime: Date.now(),
      duration: (windowHeight + extraDistance + 20 + (index * 20)) / fallSpeed * 1000,
      style: {
        zIndex: 1500,
        fontSize: '36px',
        fontWeight: 'bold',
        color: '#ff69b4',
        textShadow: '0 0 8px #ff69b4'
      }
    }))

    // Add the trail to matrixChars immediately
    setMatrixChars(prev => {
      const now = Date.now()
      const filtered = prev
        .filter(char => now - char.startTime < char.duration)
        .slice(-MAX_MATRIX_CHARS + trail.length)
      return [...filtered, ...trail]
    })

    // Set timeout to trigger reward when 0day reaches bottom
    setTimeout(() => {
      // Create flash effect
      const flash = document.createElement('div')
      flash.className = 'column-flash'
      flash.style.left = `${x - 50}px`
      document.body.appendChild(flash)
      
      // Remove flash after animation
      setTimeout(() => flash.remove(), 500)

      // Add explosion effect
      const explosion = Array.from({ length: 15 }, (_, i) => ({
        char: matrixCharacters[Math.floor(Math.random() * matrixCharacters.length)],
        x: x + (Math.random() * 200 - 100),
        y: windowHeight - 100 + (Math.random() * 200 - 100),
        id: `explosion-${baseId}-${i}`,
        opacity: 1,
        isExplosion: true
      }))

      // Remove 0day and add explosion
      setMatrixChars(prev => [
        ...prev.filter(c => !c.isZeroday || Math.floor(c.id) !== Math.floor(baseId)),
        ...explosion
      ])

      // Add points
      const zerodayPoints = 1000 + (multipliers.zerodayBonus || 0)
      setScore(prev => Math.min(prev + zerodayPoints, Number.MAX_SAFE_INTEGER))
    }, (windowHeight + extraDistance) / fallSpeed * 1000)

    return {
      id: baseId,
      x,
      y: -20,
      trail,
      startTime: Date.now(),
      duration: (windowHeight + extraDistance + 300) / fallSpeed * 1000
    }
  }

  // Update the click margin check function
  const isNearZeroday = (clickX, clickY, zerodayX, baseY, createdAt) => {
    const margin = 100
    const timeSinceCreation = Date.now() - createdAt
    const currentY = baseY + (timeSinceCreation * 0.1) // Adjust this value to match fall speed
    return Math.abs(clickX - zerodayX) <= margin && Math.abs(clickY - currentY) <= margin
  }

  useEffect(() => {
    const handleKeyPress = (e) => {
      if (e.repeat) return
      handleInteraction({})
    }
    
    window.addEventListener('keydown', handleKeyPress)
    window.addEventListener('click', handleInteraction)
    return () => {
      window.removeEventListener('keydown', handleKeyPress)
      window.removeEventListener('click', handleInteraction)
    }
  }, [multipliers]) // Add multipliers as a dependency

  useEffect(() => {
    if (score >= 50 && !showHackButton) {
      setShowHackButton(true)
    }
  }, [score])

  const getInstructionText = () => {
    const rank = getRank().name
    
    if (isGlitchMode) {
      // Glitch mode messages
      switch (rank) {
        case 'Script Kiddie':
          return "THE MACHINE YEARNS FOR HACKS"
        case 'Malware Developer':
          return "HACK THE GIBSON"
        case 'C2 Operator':
          return "THE GREAT FIREWALL CRUMBLES"
        case 'State-sponsored Actor':
          return "WI-FI FOR THE WI-FI GODS"
        case 'APT':
          return "AS THEY SNOOP ON US"
        case 'AI 0day':
          return "THE SPOON BENDS"
        default:
          return "THE MACHINE YEARNS FOR HACKS"
      }
    } else {
      // Normal mode messages
      switch (rank) {
        case 'Script Kiddie':
          return "CLICK ANYWHERE OR PRESS ANY KEY TO HACK. Unlock the HACK store to buy upgrades."
        case 'Malware Developer':
          return "Hack the planet!"
        case 'C2 Operator':
          return "The quieter you become, the louder you can fart."
        case 'State-sponsored Actor':
          return "RISC architecture is going to change everything."
        case 'APT':
          return "The pool on the roof must have a leak."
        case 'AI 0day':
          return "Crash and Burn"
        default:
          return "CLICK ANYWHERE OR PRESS ANY KEY TO HACK"
      }
    }
  }

  const getRank = () => {
    // Calculate total upgrades purchased across all hacks, excluding glitch
    const totalUpgrades = Object.entries(ownedHacks).reduce((sum, [hackId, level]) => 
      hackId === 'glitch' ? sum : sum + level, 0
    )
    
    // Each rank requires 20 more upgrades
    if (totalUpgrades >= 100) return { name: 'AI 0day', color: '#ff0000' }         // Red
    if (totalUpgrades >= 80) return { name: 'APT', color: '#ffd700' }              // Gold
    if (totalUpgrades >= 60) return { name: 'State-sponsored Actor', color: '#ff69b4' } // Pink
    if (totalUpgrades >= 40) return { name: 'C2 Operator', color: '#a020f0' }      // Purple
    if (totalUpgrades >= 20) return { name: 'Malware Developer', color: '#4169e1' } // Blue
    return { name: 'Script Kiddie', color: '#808080' }                             // Gray
  }

  const getStatsText = () => {
    const stats = []
    
    // Calculate rank info, excluding glitch from total upgrades
    const totalUpgrades = Object.entries(ownedHacks).reduce((sum, [hackId, level]) => 
      hackId === 'glitch' ? sum : sum + level, 0
    )
    
    const rank = getRank()
    const nextRankThreshold = 
      totalUpgrades < 20 ? 20 :
      totalUpgrades < 40 ? 40 :
      totalUpgrades < 60 ? 60 :
      totalUpgrades < 80 ? 80 :
      totalUpgrades < 100 ? 100 : null

    // Add rank with progress
    stats.push(`RANK: ${rank.name}`)
    if (nextRankThreshold) {
      stats.push(`Progress: ${totalUpgrades}/${nextRankThreshold}`)
    } else {
      stats.push('Maximum Rank!')
    }
    stats.push('') // Empty line for spacing

    // Add glitch level in glitch mode
    if (isGlitchMode) {
      const glitchText = "GLITCH LEVEL: " + ownedHacks.glitch
      const chars = glitchText.split('').map((char, i) => 
        `<span class="static-rainbow-char" style="animation: scoreGlitch16Colors 4s linear infinite !important;" data-char="${char}">${char}</span>`
      ).join('')
      stats.push(chars)
      stats.push('') // Empty line after glitch level
    }
    
    const criticalChance = (getCriticalChance() * 100).toFixed(2)
    stats.push(`<span style="color: #ff0000">CRITICAL: ${criticalChance}% (${getCritMultiplier()}x multi)</span>`)

    // Show legendary chance if Unauth RCE is owned
    if (ownedHacks.unauthRce > 0) {
      const legendaryChance = ((multipliers.legendaryChance || 0) * 100).toFixed(2)
      const legendaryMulti = multipliers.legendaryMultiplier || 100
      stats.push(`<span style="color: #ffa500">LEGENDARY: ${legendaryChance}% (${legendaryMulti}x multi)</span>`)
    }

    const doubleClickChance = (getDoubleClickChance() * 100).toFixed(2)
    if (parseFloat(doubleClickChance) > 0) {
      stats.push(`<span style="color: #0f0">DOUBLE: ${doubleClickChance}%</span>`)
    }

    // Show 0day chance if NOP Sled is owned or base chance exists
    const totalZerodayChance = multipliers.baseZerodayChance + (multipliers.zerodayChance || 0)
    const zerodayReward = 1000 + (multipliers.zerodayBonus || 0)
    stats.push(`<span style="color: #ff69b4">0DAY: ${totalZerodayChance.toFixed(1)}% (${formatNumber(zerodayReward)} pts)</span>`)

    if (multipliers.hacksPerSecond > 0) {
      stats.push(`<span style="color: #0f0">HACKS/SEC: ${multipliers.hacksPerSecond.toFixed(1)}</span>`)
    }

    return stats.join('\n')
  }

  // More efficient auto-hack scheduling
  useEffect(() => {
    if (multipliers.hacksPerSecond > 0) {
      const interval = setInterval(() => {
        handleInteraction({})
      }, 1000 / multipliers.hacksPerSecond)

      return () => clearInterval(interval)
    }
  }, [multipliers.hacksPerSecond])

  // Add 0day spawn effect
  useEffect(() => {
    const interval = setInterval(() => {
      const totalZerodayChance = (multipliers.baseZerodayChance + (multipliers.zerodayChance || 0)) / 100
      if (Math.random() < totalZerodayChance) {
        const zerodayInfo = addZeroday()
        setZerodays(prev => [...prev, zerodayInfo])

        setTimeout(() => {
          setZerodays(prev => prev.filter(z => z.id !== zerodayInfo.id))
        }, zerodayInfo.duration)
      }
    }, 1000)

    return () => clearInterval(interval)
  }, [multipliers.zerodayChance, multipliers.baseZerodayChance])

  // Effect for counting 0days
  useEffect(() => {
    const count0days = setInterval(() => {
      const now = Date.now()
      setMatrixChars(prev => {
        prev.forEach(char => {
          if (char.isZeroday && !counted0days.has(char.id)) {
            const isFirstInTrail = !prev.some(other => 
              other.isZeroday && 
              Math.abs(other.x - char.x) < 5 && 
              other.y < char.y
            )

            if (isFirstInTrail && now - char.startTime >= char.duration) {
              const zerodayReward = 1000 + (multipliers.zerodayBonus || 0)
              //console.log(`0day counted! Points: ${zerodayReward.toLocaleString()}`)
              setScore(prevScore => Math.min(prevScore + zerodayReward, Number.MAX_SAFE_INTEGER))
              setCounted0days(prev => new Set([...prev, char.id]))
            }
          }
        })
        return prev
      })
    }, 100)

    return () => clearInterval(count0days)
  }, [multipliers.zerodayBonus, counted0days])

  // Separate cleanup effect for non-0day characters
  useEffect(() => {
    const cleanup = setInterval(() => {
      const now = Date.now()
      setMatrixChars(prev => 
        prev.filter(char => 
          char.isZeroday || // Keep all 0days
          now - char.startTime < char.duration
        ).slice(-MAX_MATRIX_CHARS)
      )
    }, 500)

    return () => clearInterval(cleanup)
  }, [])

  // Add effect to handle rank transitions
  useEffect(() => {
    const currentRank = getRank().name
    if (previousRank && currentRank !== previousRank) {
      setIsTransitioning(true)
      setTimeout(() => {
        setIsTransitioning(false)
      }, 500) // Match CSS transition duration
    }
    setPreviousRank(currentRank)
  }, [getRank().name])

  const formatNumber = (num) => {
    return num.toLocaleString()
  }

  useEffect(() => {
    // Only load from localStorage if we don't have a glitch level yet
    if (ownedHacks.glitch === 0) {
      const savedGlitchLevel = parseInt(localStorage.getItem('glitchLevel') || '0')
      if (savedGlitchLevel > 0) {
        setOwnedHacks(prev => ({
          ...prev,
          glitch: savedGlitchLevel
        }))
      }
    }
  }, []) // Empty dependency array means this runs once on mount

  useEffect(() => {
    if (isGlitchMode) {
      const interval = setInterval(() => {
        const chars = document.querySelectorAll('.static-rainbow-char')
        if (chars.length > 0) {
          const startIndex = Math.floor(Math.random() * chars.length)
          const length = Math.floor(Math.random() * 3) + 3
          
          for (let i = 0; i < length; i++) {
            const index = (startIndex + i) % chars.length
            const char = chars[index]
            // Remove and re-add the animation to restart it
            char.style.animation = 'none'
            char.offsetHeight // Trigger reflow
            char.style.animation = 'glitchFlash 2s linear'
          }
        }
      }, 100) // Run more frequently

      return () => clearInterval(interval)
    }
  }, [isGlitchMode])

  // Add this function to generate random bright colors for the glitch text
  const getRandomBrightColor = () => {
    const hue = Math.floor(Math.random() * 360)
    return `hsl(${hue}, 100%, 50%)`
  }

  // Add this effect near your other useEffects
  useEffect(() => {
    // Only run in glitch mode level 10+
    if (isGlitchMode && ownedHacks.glitch >= 10) {
      const interval = setInterval(() => {
        const x = Math.random() * window.innerWidth
        const color = `hsl(${Math.random() * 360}, 100%, 50%)`
        
        const flash = document.createElement('div')
        flash.className = 'column-flash glitch-10'
        flash.style.left = `${x}px`
        flash.style.background = `linear-gradient(transparent, ${color}, transparent)`
        document.body.appendChild(flash)

        // Remove the flash element after animation completes
        flash.addEventListener('animationend', () => {
          flash.remove()
        })
      }, ownedHacks.glitch >= 18 ? 1667 : 5000) // 3x more frequent at level 18+

      return () => clearInterval(interval)
    }
  }, [isGlitchMode, ownedHacks.glitch])

  return (
    <>
      <div className={`matrix-background ${isGlitchMode ? 'glitch-mode' : ''}`}
           data-glitch-level={isGlitchMode && ownedHacks.glitch >= 16 ? "16" : undefined}>
        {matrixChars.map(({ char, x, y, id, opacity, isCritical, isExplosion, isZeroday, isLegendary, style }) => (
          <span
            key={id}
            className={`matrix-character 
              ${isCritical ? 'critical' : ''} 
              ${isLegendary ? 'legendary' : ''}
              ${isExplosion ? 'explosion' : ''} 
              ${isZeroday ? 'zeroday' : ''}`}
            style={{
              left: `${x}px`,
              top: `${y}px`,
              opacity,
              ...(isZeroday ? style : {}),
              ...(isGlitchMode ? {
                '--random': Math.random(),
                ...(isZeroday ? {
                  '--base-color': '#ff69b4',
                  animation: 'fall 4s linear forwards, rotateHue 1s linear infinite'
                } : isCritical ? {
                  '--base-color': '#ff0000',
                  animation: 'fall 2s linear forwards, rotateHue 1s linear infinite'
                } : isLegendary ? {
                  '--base-color': '#ffa500',
                  animation: 'fall 2s linear forwards, rotateHue 1s linear infinite'
                } : {
                  '--random': Math.random()
                })
              } : {})
            }}
          >
            {char}
          </span>
        ))}
      </div>
      <div className={`game-container ${isGlitchMode ? 'glitch-mode' : ''}`} 
           style={{ pointerEvents: isUIDisabled ? 'none' : 'auto' }}>
        <div className="score" data-glitch-level={
          isGlitchMode && ownedHacks.glitch >= 16 ? "16" : 
          isGlitchMode && ownedHacks.glitch >= 10 ? "10" : 
          undefined
        }>
          {isGlitchMode && (ownedHacks.glitch >= 10) ? (
            formatNumber(score).split('').map((char, i) => (
              <span key={i} className="static-rainbow-char" data-char={zalgo(char)}>{zalgo(char)}</span>
            ))
          ) : (
            isGlitchMode ? zalgo(formatNumber(score)) : formatNumber(score)
          )}
        </div>
        <div className="instruction-text" 
             data-glitch-level={isGlitchMode && ownedHacks.glitch >= 10 ? "10" : undefined}>
          {isGlitchMode ? (
            <>
              {zalgo(getInstructionText())}
              <br />
              <span className="critical-text" style={{ whiteSpace: 'pre-line', color: '#800080' }}>
                <span style={{ color: '#d000d0', fontWeight: 'bold' }}>
                  {getStatsText().split('\n')[0]}
                </span>
                <span 
                  className="stats-text"
                  dangerouslySetInnerHTML={{ 
                    __html: '\n' + getStatsText().split('\n').slice(1).join('\n')
                  }}
                />
              </span>
            </>
          ) : (
            <>
              {getInstructionText()}
              <br />
              <span className="critical-text" style={{ whiteSpace: 'pre-line' }}>
                <span style={{ color: getRank().color, fontWeight: 'bold' }}>
                  {getStatsText().split('\n')[0]}
                </span>
                <span dangerouslySetInnerHTML={{ 
                  __html: '\n' + getStatsText().split('\n').slice(1).join('\n')
                }} />
              </span>
            </>
          )}
        </div>
        {showHackButton && (
          <div className="hack-button-container">
            <button 
              className={`hack-button ${!hasClickedHackButton ? 'first-time' : ''}`}
              data-glitch-level={
                isGlitchMode && ownedHacks.glitch >= 18 ? "18" : 
                isGlitchMode && ownedHacks.glitch >= 10 ? "10" : 
                undefined
              }
              onClick={handleHack}
            >
              HACK!
        </button>
          </div>
        )}
      </div>
      {showHackOverlay && !isUIDisabled && (
        <div className={`hack-overlay ${isGlitchMode ? 'glitch-mode' : ''}`}>
          <div className="hack-overlay-content">
            <button className="close-button" onClick={() => setShowHackOverlay(false)}>×</button>
            <h2>Available Hacks</h2>
            {Object.entries(RANK_HACKS)
              .filter(([rank]) => {
                const currentRank = getRank().name
                const ranks = ['Script Kiddie', 'Malware Developer', 'C2 Operator', 'State-sponsored Actor', 'APT', 'AI 0day']
                return ranks.indexOf(rank) <= ranks.indexOf(currentRank)
              })
              .map(([rank, hacks]) => {
                // Check if all hacks in this rank group are hidden
                const allHacksHidden = Object.keys(hacks).every(hackId => 
                  // Don't hide the glitch hack even in glitch mode
                  hackId !== 'glitch' && hiddenHacks.includes(hackId)
                )

                // Skip rendering this rank group if all hacks are hidden
                if (allHacksHidden) return null

                return (
                  <div key={rank} className={`hack-rank-group ${
                    isTransitioning && rank === getRank().name ? 'fading-in' : 
                    isTransitioning && rank === previousRank ? 'fading-out' : ''
                  }`}>
                    <h3 style={{ color: getRank().color }}>{rank}</h3>
                    {Object.entries(hacks).map(([hackId, hack]) => {
                      const currentLevel = ownedHacks[hackId]
                      const cost = getHackCost(hackId)
                      const canAfford = score >= cost
                      const maxedOut = currentLevel >= hack.maxLevel

                      // Don't hide glitch hack in glitch mode
                      if (hiddenHacks.includes(hackId) && hackId !== 'glitch') return null

                      // Hide Flipper Zero unless glitch level >= 4 and rank is AI 0day
                      if (hackId === 'flipperZero' && (ownedHacks.glitch < 4 || getRank().name !== 'AI 0day')) {
                        return null
                      }

                      // Hide ROWHAMMER unless glitch level >= 6 and rank is AI 0day
                      if (hackId === 'rowHammer' && (ownedHacks.glitch < 6 || getRank().name !== 'AI 0day')) {
                        return null
                      }

                      // Hide BAN C++ unless glitch level >= 10 and rank is AI 0day
                      if (hackId === 'banCpp' && (ownedHacks.glitch < 10 || getRank().name !== 'AI 0day')) {
                        return null
                      }

                      // Hide Enable MFA unless glitch level >= 16 and rank is AI 0day
                      if (hackId === 'enableMfa' && (ownedHacks.glitch < 16 || getRank().name !== 'AI 0day')) {
                        return null
                      }

                      // Hide all other hacks when glitch level >= 18
                      if (ownedHacks.glitch >= 18 && getRank().name === 'AI 0day') {
                        if (hackId !== 'ascend') {
                          return null
                        }
                      }

                      // Hide ascend unless glitch level >= 18 and rank is AI 0day
                      if (hackId === 'ascend' && (ownedHacks.glitch < 18 || getRank().name !== 'AI 0day')) {
                        return null
                      }

                      return (
                        <div 
                          key={hackId} 
                          className={`hack-item ${maxedOut ? 'maxed-out' : ''} ${
                            hackId === 'glitch' ? 'glitch' : 
                            hackId === 'flipperZero' || hackId === 'rowHammer' ? 'flipper-zero' : ''
                          }`}
                          data-hack-id={hackId}
                        >
                          <div className="hack-info">
                            <h3 data-text={hack.name}>
                              {hack.name}
                              {currentLevel > 0 && (
                                <div className="level-progress">
                                  <div 
                                    className="level-progress-fill" 
                                    style={{ 
                                      width: `${(currentLevel / hack.maxLevel) * 100}%` 
                                    }}
                                  />
                                  <span className="level-progress-text">
                                    lvl {currentLevel}
                                  </span>
                                </div>
                              )}
                            </h3>
                            <p data-text={hack.description}>{hack.description}</p>
                            <p className="cost-text" data-text={maxedOut ? 'MAXED OUT' : `Cost: ${formatNumber(cost)} points`}>
                              {maxedOut ? 'MAXED OUT' : `Cost: ${formatNumber(cost)} points`}
                            </p>
                          </div>
                          <button 
                            className={`buy-button ${maxedOut ? 'owned' : ''} ${canAfford && !maxedOut ? 'can-afford' : ''}`}
                            onClick={() => handleBuyHack(hackId)}
                            disabled={maxedOut || !canAfford}
                          >
                            {maxedOut ? 'MAXED' : 'BUY'}
                          </button>
                        </div>
                      )
                    })}
                  </div>
                )
              })}
          </div>
        </div>
      )}
    </>
  )
}

export default App
