import "androguard"

rule Everything
      {
        meta:
          date = "2022/01"

        condition:
        	androguard.package_name(/.*/)
      }
