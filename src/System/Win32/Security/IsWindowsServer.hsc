{-# LANGUAGE CPP #-}
module System.Win32.Security.IsWindowsServer
  ( isWindowsServer
  , isMajorVersion
  ) where

#include <windows.h>
import Foreign.C.String      (withCString, peekCString)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Storable      (Storable (peek, poke, sizeOf, alignment, peekByteOff, pokeByteOff))
import Foreign.Ptr           (Ptr, plusPtr)
import System.Win32.Types    (BYTE, WORD, DWORD, DDWORD, LPWSTR)


-- c structures

-- | Type of os: windows server, windows home edition, etc
data ProductType = VerUnknow BYTE | VerNTWorkStation | VerNTDomainControler | VerNTServer
  deriving (Show,Eq)

instance Storable ProductType where
  sizeOf    _ = sizeOf    (undefined::BYTE)
  alignment _ = alignment (undefined::BYTE)
  poke buf v = pokeByteOff buf 0 $ case v of
      VerUnknow w          -> w
      VerNTWorkStation     -> #const VER_NT_WORKSTATION
      VerNTDomainControler -> #const VER_NT_DOMAIN_CONTROLLER
      VerNTServer          -> #const VER_NT_SERVER
  peek buf = do
      v <- peekByteOff buf 0
      return $ case v of
          (#const VER_NT_WORKSTATION)       -> VerNTWorkStation
          (#const VER_NT_DOMAIN_CONTROLLER) -> VerNTDomainControler
          (#const VER_NT_SERVER)            -> VerNTServer
          w                                 -> VerUnknow w


-- | All os information. See MSDN for reference
data OSVERSIONINFOEX = OSVERSIONINFOEX
     { dwMajorVersion    :: DWORD
     , dwMinorVersion    :: DWORD
     , dwBuildNumber     :: DWORD
     , dwPlatformId      :: DWORD
     , szCSDVersion      :: String
     , wServicePackMajor :: WORD
     , wServicePackMinor :: WORD
     , wSuiteMask        :: WORD
     , wProductType      :: ProductType
     } deriving Show

instance Storable OSVERSIONINFOEX where
    sizeOf = const #{size struct _OSVERSIONINFOEXW}
    alignment _ = #alignment OSVERSIONINFOEX
    poke buf info = do
        (#poke OSVERSIONINFOEXW, dwOSVersionInfoSize) buf (sizeOf info)
        (#poke OSVERSIONINFOEXW, dwMajorVersion) buf (dwMajorVersion info)
        (#poke OSVERSIONINFOEXW, dwMinorVersion) buf (dwMinorVersion info)
        (#poke OSVERSIONINFOEXW, dwBuildNumber)  buf (dwBuildNumber info)
        (#poke OSVERSIONINFOEXW, dwPlatformId) buf (dwPlatformId info)
        withCString (szCSDVersion info) $ \szCSDVersion' ->
          (#poke OSVERSIONINFOEXW, szCSDVersion) buf szCSDVersion'
        (#poke OSVERSIONINFOEXW, wServicePackMajor) buf (wServicePackMajor info)
        (#poke OSVERSIONINFOEXW, wServicePackMinor) buf (wServicePackMinor info)
        (#poke OSVERSIONINFOEXW, wSuiteMask)   buf (wSuiteMask info)
        (#poke OSVERSIONINFOEXW, wProductType) buf (wProductType info)
        (#poke OSVERSIONINFOEXW, wReserved)    buf (0::BYTE)

    peek buf = do
        majorVersion     <- (#peek OSVERSIONINFOEXW, dwMajorVersion) buf
        minorVersion     <- (#peek OSVERSIONINFOEXW, dwMinorVersion) buf
        buildNumber      <- (#peek OSVERSIONINFOEXW, dwBuildNumber) buf
        platformId       <- (#peek OSVERSIONINFOEXW, dwPlatformId) buf
        cSDVersion       <- peekCString $ (#ptr OSVERSIONINFOEXW, szCSDVersion) buf
        servicePackMajor <- (#peek OSVERSIONINFOEXW, wServicePackMajor) buf
        servicePackMinor <- (#peek OSVERSIONINFOEXW, wServicePackMinor) buf
        suiteMask        <- (#peek OSVERSIONINFOEXW, wSuiteMask) buf
        productType      <- (#peek OSVERSIONINFOEXW, wProductType) buf
        return $ OSVERSIONINFOEX majorVersion minorVersion
                                 buildNumber platformId cSDVersion
                                 servicePackMajor servicePackMinor
                                 suiteMask productType


type POSVERSIONINFOEX = Ptr OSVERSIONINFOEX
type LPOSVERSIONINFOEX = Ptr OSVERSIONINFOEX

-- | Run C function on os-info structure, safely allocate memory and write
withOSVERSIONINFOEX :: OSVERSIONINFOEX -> (Ptr OSVERSIONINFOEX -> IO a) -> IO a
withOSVERSIONINFOEX value func = do
  alloca $ \buffer -> do
    poke buffer value
    func buffer

-- function imports


-- BOOL VerifyVersionInfoA(
--   LPOSVERSIONINFOEXW lpVersionInformation,
--   DWORD              dwTypeMask,
--   DWORDLONG          dwlConditionMask
-- );
foreign import stdcall unsafe "Winbase.h VerifyVersionInfoW"
  c_VerifyVersionInfoW
    :: Ptr OSVERSIONINFOEX
    -> DWORD
    -> DDWORD
    -> IO Bool


-- NTSYSAPI ULONGLONG VerSetConditionMask(
--   ULONGLONG ConditionMask,
--   DWORD     TypeMask,
--   BYTE      Condition
-- );
foreign import stdcall unsafe "Winnt.h VerSetConditionMask"
  c_VerSetConditionMask
    :: DDWORD
    -> DWORD
    -> BYTE
    -> IO DDWORD


-- real function


-- | Check if product type corresponds to Windows NT Server
isWindowsServer :: IO Bool
isWindowsServer = do
  let verInfoPattern = OSVERSIONINFOEX {
        -- these are ignored because of comparison mask
          dwMajorVersion = 0
        , dwMinorVersion = 0
        , dwBuildNumber  = 0
        , dwPlatformId   = 0
        , szCSDVersion   = ""
        , wServicePackMajor = 0
        , wServicePackMinor = 0
        , wSuiteMask = 0
        -- the important part
        , wProductType = VerNTServer
        }
  typeMask <- c_VerSetConditionMask 0 -- initial zero mask
                                    (#const VER_PRODUCT_TYPE)
                                    (#const VER_EQUAL)
  withOSVERSIONINFOEX verInfoPattern
    $ \pattern -> c_VerifyVersionInfoW pattern (#const VER_PRODUCT_TYPE) typeMask


-- | Check if OS major version is same as parameter. For windows 10 it's 6.
-- Useful for testing if your ffi works correctly.
isMajorVersion :: Int -> IO Bool
isMajorVersion val = do
  let verInfoPattern = OSVERSIONINFOEX {
          dwMajorVersion = fromIntegral val
        , dwMinorVersion = 0
        , dwBuildNumber  = 0
        , dwPlatformId   = 0
        , szCSDVersion   = ""
        , wServicePackMajor = 0
        , wServicePackMinor = 0
        , wSuiteMask = 0
        , wProductType = VerUnknow 0
        }
  typeMask <- c_VerSetConditionMask 0 -- initial zero mask
                                    (#const VER_MAJORVERSION)
                                    (#const VER_EQUAL)
  withOSVERSIONINFOEX verInfoPattern $ \buf ->
    c_VerifyVersionInfoW buf (#const VER_MAJORVERSION) typeMask
