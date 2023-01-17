import "androguard"

rule SampleRuleset
      {
        meta:
          date = "2022/01"

        condition:
        	androguard.package_name(/.*/)
      }
