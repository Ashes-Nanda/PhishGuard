import { extendTheme, ThemeConfig } from '@chakra-ui/react'

const config: ThemeConfig = {
  initialColorMode: 'dark',
  useSystemColorMode: false,
}

export const theme = extendTheme({
  config,
  colors: {
    primary: {
      50: '#E5FFF9',
      100: '#B8FFE9',
      200: '#8AFFD9',
      300: '#5CFFC9',
      400: '#2EFFB9',
      500: '#00FFA9',
      600: '#00CC87',
      700: '#009965',
      800: '#006643',
      900: '#003321',
    },
    secondary: {
      50: '#FFE5F2',
      100: '#FFB8DC',
      200: '#FF8AC6',
      300: '#FF5CB0',
      400: '#FF2E9A',
      500: '#FF0084',
      600: '#CC0069',
      700: '#99004F',
      800: '#660034',
      900: '#33001A',
    },
    darkBg: {
      900: '#0A0F1B',
      800: '#111827',
      700: '#1F2937',
      600: '#374151',
    },
    glassDark: 'rgba(0, 0, 0, 0.3)',
    glassStroke: 'rgba(255, 255, 255, 0.1)',
  },
  fonts: {
    heading: '"Inter", system-ui, sans-serif',
    body: '"Inter", system-ui, sans-serif',
  },
  styles: {
    global: {
      body: {
        bg: 'darkBg.900',
        color: 'whiteAlpha.900',
        backgroundImage: 'radial-gradient(circle at 50% 0%, rgba(0, 255, 169, 0.15), transparent 50%), radial-gradient(circle at 100% 0%, rgba(255, 0, 132, 0.15), transparent 50%)',
        backgroundAttachment: 'fixed',
      },
    },
  },
  components: {
    Button: {
      baseStyle: {
        fontWeight: '600',
        borderRadius: 'xl',
        _focus: {
          boxShadow: '0 0 0 3px rgba(0, 255, 169, 0.4)',
        },
      },
      variants: {
        primary: {
          bg: 'primary.500',
          color: 'darkBg.900',
          _hover: {
            bg: 'primary.400',
            transform: 'translateY(-2px)',
            boxShadow: 'lg',
          },
          _active: {
            bg: 'primary.600',
            transform: 'translateY(0)',
          },
        },
        secondary: {
          bg: 'secondary.500',
          color: 'white',
          _hover: {
            bg: 'secondary.400',
            transform: 'translateY(-2px)',
            boxShadow: 'lg',
          },
          _active: {
            bg: 'secondary.600',
            transform: 'translateY(0)',
          },
        },
        glass: {
          bg: 'glassDark',
          backdropFilter: 'blur(10px)',
          borderWidth: '1px',
          borderColor: 'glassStroke',
          color: 'whiteAlpha.900',
          _hover: {
            bg: 'whiteAlpha.200',
            transform: 'translateY(-2px)',
            boxShadow: 'lg',
          },
        },
      },
    },
    Box: {
      variants: {
        glass: {
          bg: 'glassDark',
          backdropFilter: 'blur(10px)',
          borderWidth: '1px',
          borderColor: 'glassStroke',
          borderRadius: 'xl',
        },
      },
    },
    Card: {
      baseStyle: {
        container: {
          bg: 'glassDark',
          backdropFilter: 'blur(10px)',
          borderRadius: 'xl',
          borderWidth: '1px',
          borderColor: 'glassStroke',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3)',
          transition: 'all 0.2s ease-in-out',
          _hover: {
            transform: 'translateY(-2px)',
            boxShadow: '0 12px 48px rgba(0, 0, 0, 0.4)',
          },
        },
      },
    },
    Text: {
      baseStyle: {
      color: 'whiteAlpha.900',
      textShadow: '0 1px 2px rgba(0, 0, 0, 0.2)',
      },
      variants: {
      muted: {
        color: 'whiteAlpha.800',
      },
      gradient: {
        bgGradient: 'linear(to-r, primary.400, secondary.400)',
        bgClip: 'text',
        fontWeight: 'bold',
      },
      },
    },
    Heading: {
      baseStyle: {
      color: 'whiteAlpha.900',
      textShadow: '0 2px 4px rgba(0, 0, 0, 0.3)',
      },
      variants: {
      gradient: {
        bgGradient: 'linear(to-r, primary.400, secondary.400)',
        bgClip: 'text',
        textShadow: 'none',
      },
      },
    },
    Badge: {
      baseStyle: {
      color: 'whiteAlpha.900',
      bg: 'glassDark',
      backdropFilter: 'blur(10px)',
      borderWidth: '1px',
      borderColor: 'glassStroke',
      textShadow: '0 1px 2px rgba(0, 0, 0, 0.2)',
      boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)',
      },
    },
    Alert: {
      baseStyle: {
      container: {
        bg: 'glassDark',
        backdropFilter: 'blur(10px)',
        borderWidth: '1px',
        borderColor: 'glassStroke',
        boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
      },
      title: {
        color: 'whiteAlpha.900',
        textShadow: '0 1px 2px rgba(0, 0, 0, 0.2)',
      },
      description: {
        color: 'whiteAlpha.800',
      },
      icon: {
        color: 'primary.400',
      },
      },
    },
    Link: {
      baseStyle: {
      color: 'primary.400',
      _hover: {
        textDecoration: 'none',
        color: 'primary.300',
      },
      },
    },
    FormLabel: {
      baseStyle: {
      color: 'whiteAlpha.900',
      textShadow: '0 1px 2px rgba(0, 0, 0, 0.2)',
      marginBottom: '2',
      },
    },
    Input: {
      variants: {
      filled: {
        field: {
        bg: 'darkBg.700',
        color: 'whiteAlpha.900',
        borderColor: 'glassStroke',
        _placeholder: {
          color: 'whiteAlpha.500',
        },
        _hover: {
          bg: 'darkBg.600',
          borderColor: 'primary.400',
        },
        _focus: {
          bg: 'darkBg.600',
          borderColor: 'primary.400',
          boxShadow: '0 0 0 1px var(--chakra-colors-primary-400)',
        },
        },
      },
      },
      defaultProps: {
      variant: 'filled',
      },
    },
    Select: {
      variants: {
      filled: {
        field: {
        bg: 'darkBg.700',
        color: 'whiteAlpha.900',
        borderColor: 'glassStroke',
        _hover: {
          bg: 'darkBg.600',
          borderColor: 'primary.400',
        },
        _focus: {
          bg: 'darkBg.600',
          borderColor: 'primary.400',
          boxShadow: '0 0 0 1px var(--chakra-colors-primary-400)',
        },
        },
      },
      },
      defaultProps: {
      variant: 'filled',
      },
    },
    Modal: {
      baseStyle: {
      dialog: {
      bg: 'darkBg.800',
      borderColor: 'glassStroke',
      backdropFilter: 'blur(10px)',
      },
      header: {
      color: 'whiteAlpha.900',
      },
      body: {
      color: 'whiteAlpha.800',
      },
      },
    },
    Textarea: {
      variants: {
      filled: {
        bg: 'darkBg.700',
        color: 'whiteAlpha.900',
        borderColor: 'glassStroke',
        _placeholder: {
        color: 'whiteAlpha.500',
        },
        _hover: {
        bg: 'darkBg.600',
        borderColor: 'primary.400',
        },
        _focus: {
        bg: 'darkBg.600',
        borderColor: 'primary.400',
        boxShadow: '0 0 0 1px var(--chakra-colors-primary-400)',
        },
      },
      },
      defaultProps: {
      variant: 'filled',
      },
    },
    Tooltip: {
      baseStyle: {
      bg: 'darkBg.800',
      color: 'whiteAlpha.900',
      borderWidth: '1px',
      borderColor: 'glassStroke',
      backdropFilter: 'blur(10px)',
      boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
      },
    },
    IconButton: {
      variants: {
      ghost: {
      color: 'whiteAlpha.900',
      _hover: {
      bg: 'whiteAlpha.100',
      transform: 'translateY(-2px)',
      },
      _active: {
      transform: 'translateY(0)',
      },
      },
      },
    },
    Accordion: {
      baseStyle: {
      container: {
        bg: 'glassDark',
        borderColor: 'glassStroke',
        borderWidth: '1px',
        borderRadius: 'xl',
        backdropFilter: 'blur(10px)',
      },
      button: {
        color: 'whiteAlpha.900',
        _hover: {
        bg: 'whiteAlpha.100',
        },
      },
      panel: {
        color: 'whiteAlpha.800',
      },
      },
    },
    List: {
      baseStyle: {
      item: {
        color: 'whiteAlpha.900',
      },
      icon: {
        color: 'primary.400',
      },
      },
    },
    Divider: {
      baseStyle: {
      borderColor: 'glassStroke',
      opacity: 0.2,
      },
    },
    },
    })
