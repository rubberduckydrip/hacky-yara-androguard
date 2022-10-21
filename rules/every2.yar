import "androguard"

rule Everything2
      {
        meta:
          date = "2022/01"

        condition:
        	androguard.package_name(/.*/)
      }
