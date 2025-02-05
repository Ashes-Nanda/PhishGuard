import { extendTheme } from '@chakra-ui/react'

export const theme = extendTheme({
  colors: {
    primary: {
      500: '#00FFCC',
      600: '#00E6B8',
    },
    secondary: {
      500: '#FF007F',
      600: '#E6006F',
    },
    accent: {
      blue: '#1E90FF',
      gold: '#FFD700',
      orange: '#FF4500',
    },
  },
  fonts: {
    heading: '"Inter", sans-serif',
    body: '"Inter", sans-serif',
  },
  components: {
    Button: {
      baseStyle: {
        fontWeight: '600',
        borderRadius: 'lg',
      },
      variants: {
        primary: {
          bg: 'primary.500',
          color: 'gray.800',
          _hover: {
            bg: 'primary.600',
          },
        },
        secondary: {
          bg: 'secondary.500',
          color: 'white',
          _hover: {
            bg: 'secondary.600',
          },
        },
        warning: {
          bg: 'accent.orange',
          color: 'white',
          _hover: {
            bg: 'orange.600',
          },
        },
      },
    },
    Card: {
      baseStyle: (props: any) => ({
        container: {
          bg: props.colorMode === 'dark' 
            ? 'rgba(17, 25, 40, 0.75)' 
            : 'rgba(255, 255, 255, 0.75)',
          backdropFilter: 'blur(4px)',
          borderRadius: 'lg',
          border: '1px solid',
          borderColor: props.colorMode === 'dark' 
            ? 'rgba(255, 255, 255, 0.125)' 
            : 'rgba(255, 255, 255, 0.75)',
        },
      }),
    },
  },
  styles: {
    global: {
      body: {
        bg: 'gray.50',
      },
    },
  },
}) 