# PowerShell script setting base variables for EventMachine fat binary gem
# Code by MSP-Greg, see https://github.com/MSP-Greg/appveyor-utilities

# load utility functions, pass 64 or 32
. $PSScriptRoot\shared\appveyor_setup.ps1 $args[0]

# above is required code
#———————————————————————————————————————————————————————————————— above for all repos

Make-Const gem_name  'eventmachine'
Make-Const repo_name 'eventmachine'
Make-Const url_repo  'https://github.com/eventmachine/eventmachine.git'

#———————————————————————————————————————————————————————————————— lowest ruby version
Make-Const ruby_vers_low 20

#———————————————————————————————————————————————————————————————— make info
Make-Const dest_so  'lib'
Make-Const exts     @(
  @{ 'conf' = 'ext/extconf.rb'                ; 'so' = 'rubyeventmachine'  },
  @{ 'conf' = 'ext/fastfilereader/extconf.rb' ; 'so' = 'fastfilereaderext' }
)
Make-Const write_so_require $true

#———————————————————————————————————————————————————————————————— pre compile
function Pre-Compile {
  Check-OpenSSL
  Write-Host Compiling With $env:SSL_VERS
}

#———————————————————————————————————————————————————————————————— Run-Tests
function Run-Tests {
  Update-Gems rake, test-unit
  rake -f Rakefile_wintest -N -R norakelib | Set-Content -Path $log_name -PassThru -Encoding UTF8
  test_unit
}

#———————————————————————————————————————————————————————————————— below for all repos
# below is required code
Make-Const dir_gem  $(Convert-Path $PSScriptRoot\..)
Make-Const dir_ps   $PSScriptRoot

Push-Location $PSScriptRoot
.\shared\make.ps1
.\shared\test.ps1
Pop-Location

exit $ttl_errors_fails + $exit_code