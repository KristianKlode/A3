ZIP=kudos.zip

all: $(ZIP)

$(ZIP):
	make -C kudos/kudos/ clean
	make -C kudos/userland/ clean
	zip -r $(ZIP) \
	  kudos/kudos/ \
	  kudos/userland/ \
	  kudos/yams.conf

clean:
	rm -rf $(ZIP)

.PHONY: all clean
